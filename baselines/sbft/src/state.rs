//! The SBFT replica state machine, written sans-IO exactly like the PBFT one
//! it was forked from: every transition is a pure function from (state,
//! event) to (state, actions), with networking, signing, clocks, and storage
//! in the engine.
//!
//! Protocol shape (SBFT with c = 0, aggregated individual signatures instead
//! of threshold signatures):
//! - The view leader doubles as the collector. Replicas send a sign-share
//!   for each accepted pre-prepare to the collector only; when the collector
//!   holds a share from every replica it broadcasts an aggregated fast
//!   commit proof and everyone delivers in a single round trip and a half.
//! - Every replica arms a slow-path timer per sign-shared sequence. If the
//!   fast proof does not arrive in time (a single slow or crashed replica is
//!   enough), the replica broadcasts a PBFT-style prepare vote and the
//!   sequence falls back to the two-phase 2f+1 slow path. Receiving any
//!   prepare vote joins a replica to the slow path immediately.
//! - The election timer is identical to PBFT: it re-arms on every delivery
//!   and starts a view change with exponential backoff when it fires.
//! - View changes carry slow-path prepared certificates plus the replica's
//!   own sign-shares. A fast-committed value has a share from every correct
//!   replica, so it appears at least f+1 times in any view-change quorum;
//!   the new leader re-proposes, per sequence, the highest-view prepared
//!   certificate, else the highest-view value with f+1 sign-shares.
//! - Laggards catch up via commit certificates (fast or slow), including a
//!   targeted reply when a replica is seen voting for an already-delivered
//!   sequence (a dropped fast proof leaves exactly that trace).

use crate::config::Committee;
use crate::messages::{
    content_digest, Batch, CommitCert, NewViewMsg, Phase, PreparedCert, SbftMessage, Seq,
    ShareEvidence, View, ViewChangeMsg, Vote,
};
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Max sequences in flight beyond the last delivered one.
pub const WATERMARK_WINDOW: Seq = 128;
/// Max commit certificates returned per sync reply.
const SYNC_REPLY_LIMIT: usize = 64;

/// Inputs to the state machine. Signatures and certificate well-formedness
/// are already verified by the engine.
#[derive(Debug)]
pub enum Event {
    PrePrepare(Batch),
    /// A sign-share, prepare, or commit vote (sign-shares reach only the
    /// collector and the sender itself).
    Vote(Vote),
    /// A verified fast or slow commit proof broadcast by the collector.
    FastCommit(CommitCert),
    ViewChange(ViewChangeMsg),
    NewView(NewViewMsg),
    /// A batch previously deferred for payload sync is now fully available.
    PayloadReady(Batch),
    /// The election timer armed for `view` fired.
    TimerFired { view: View },
    /// The slow-path timer armed when sign-sharing (view, seq) fired.
    SlowTimerFired { view: View, seq: Seq },
    /// The engine, having confirmed `want_proposal()`, hands the leader a
    /// payload to pre-prepare.
    Propose { payload: Vec<Digest> },
    SyncRequest {
        from: Seq,
        to: Seq,
        requester: PublicKey,
    },
    /// One verified commit certificate from a sync reply.
    SyncCert(CommitCert),
    /// Periodic engine tick: re-send the outstanding sync request, if any
    /// (requests and replies can be lost under network shedding).
    SyncRetryTick,
}

/// Outputs of the state machine, executed by the engine.
#[derive(Debug)]
pub enum Action {
    /// Sign a pre-prepare batch, broadcast it, and feed it back in as
    /// Event::PrePrepare.
    SignPrePrepare {
        view: View,
        seq: Seq,
        payload: Vec<Digest>,
    },
    /// Sign a sign-share vote, send it to the collector of `view` only, and
    /// feed it back in as Event::Vote.
    SignShare {
        view: View,
        seq: Seq,
        digest: Digest,
    },
    /// Sign a prepare or commit vote, broadcast it, and feed it back in as
    /// Event::Vote.
    SignVote {
        phase: Phase,
        view: View,
        seq: Seq,
        digest: Digest,
    },
    /// Broadcast the collector's aggregated commit proof and feed it back in
    /// as Event::FastCommit. No extra signature needed: the proof is a
    /// bundle of individually signed shares.
    BroadcastFastCommit(CommitCert),
    /// Sign a view-change message, broadcast, feed back as Event::ViewChange.
    SignViewChange {
        view: View,
        last_delivered: Seq,
        prepared: Vec<PreparedCert>,
        shares: Vec<ShareEvidence>,
    },
    /// Sign the given pre-prepares and the new-view message, broadcast, feed
    /// back as Event::NewView.
    SignNewView {
        view: View,
        view_changes: Vec<ViewChangeMsg>,
        o_payloads: Vec<(Seq, Vec<Digest>)>,
    },
    /// Check payload availability with the mempool; the mempool syncs
    /// missing payloads and the engine feeds Event::PayloadReady when done.
    VerifyPayload(Batch),
    /// A sequence committed and all its predecessors are delivered.
    Deliver {
        seq: Seq,
        view: View,
        leader: PublicKey,
        payload: Vec<Digest>,
    },
    CleanupMempool {
        digests: Vec<Digest>,
        seq: Seq,
    },
    /// (Re-)arm the election timer for `view` with duration
    /// election_cell * 2^factor.
    ArmTimer { view: View, factor: u32 },
    /// Arm the slow-path fallback timer for (view, seq).
    ArmSlowTimer { view: View, seq: Seq },
    /// A genuine election timeout fired (for the learning window).
    RecordViewChange { no_progress: bool },
    Send(PublicKey, SbftMessage),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Status {
    Active,
    /// Waiting for a NewView for `target`.
    ViewChanging { target: View },
}

#[derive(Default)]
struct Entry {
    /// Accepted pre-prepare (payload verified) and its view.
    batch: Option<Batch>,
    /// Pre-prepare received but payload still syncing.
    awaiting_payload: Option<View>,
    /// All votes seen for this seq, keyed by (view, phase, author).
    /// Sign-shares accumulate here on the collector (and each replica holds
    /// its own share for view-change evidence).
    votes: HashMap<(View, Phase, PublicKey), Vote>,
    prepared: bool,
    committed: bool,
    /// Views in which we already sign-shared / prepared / committed this seq.
    we_shared: HashSet<View>,
    we_prepared: HashSet<View>,
    we_committed: HashSet<View>,
    /// Collector only: views for which the fast proof was already built.
    fast_built: HashSet<View>,
    /// Commit certificate (fast or slow), set when the seq commits.
    cert: Option<CommitCert>,
}

pub struct Sbft {
    name: PublicKey,
    committee: Committee,
    gc_depth: u64,

    view: View,
    status: Status,
    /// Leader only: next sequence to assign.
    next_seq: Seq,
    last_delivered: Seq,
    entries: BTreeMap<Seq, Entry>,
    /// Commit certificates of delivered sequences (kept for gc_depth), for
    /// laggard sync.
    delivered_certs: BTreeMap<Seq, CommitCert>,

    view_changes: BTreeMap<View, HashMap<PublicKey, ViewChangeMsg>>,
    /// The new-view we already built as leader (avoid rebuilding).
    new_view_built: HashSet<View>,

    /// The view the currently armed election timer belongs to.
    timer_view: View,
    /// Consecutive timeouts without a delivery, for timer backoff.
    timer_factor: u32,
    delivered_since_timer: bool,

    /// One outstanding laggard sync range at a time.
    outstanding_sync: Option<(Seq, Seq)>,

    /// The new-view that established the current view, kept to hand to a
    /// replica stuck in a view change the rest of the committee did not
    /// join (see handle_view_change).
    last_new_view: Option<NewViewMsg>,
    /// Per-author highest sequence seen beyond our watermark window, as
    /// laggard evidence: f+1 distinct authors operating past our horizon
    /// prove the quorum has moved on without us (see note_quorum_progress).
    beyond_window: HashMap<PublicKey, Seq>,
}

impl Sbft {
    pub fn new(name: PublicKey, committee: Committee, gc_depth: u64) -> (Self, Vec<Action>) {
        let state = Self {
            name,
            committee,
            gc_depth,
            view: 0,
            status: Status::Active,
            next_seq: 1,
            last_delivered: 0,
            entries: BTreeMap::new(),
            delivered_certs: BTreeMap::new(),
            view_changes: BTreeMap::new(),
            new_view_built: HashSet::new(),
            timer_view: 0,
            timer_factor: 0,
            delivered_since_timer: false,
            outstanding_sync: None,
            last_new_view: None,
            beyond_window: HashMap::new(),
        };
        let actions = vec![Action::ArmTimer { view: 0, factor: 0 }];
        (state, actions)
    }

    pub fn view(&self) -> View {
        self.view
    }

    pub fn last_delivered(&self) -> Seq {
        self.last_delivered
    }

    // Only the state tests observe activity directly; the engine reacts to
    // actions instead.
    #[cfg(test)]
    pub fn is_active(&self) -> bool {
        self.status == Status::Active
    }

    pub fn current_leader(&self) -> PublicKey {
        self.committee.leader(self.view)
    }

    /// The engine asks this before fetching a payload and issuing
    /// Event::Propose.
    pub fn want_proposal(&self) -> bool {
        self.status == Status::Active
            && self.current_leader() == self.name
            && self.next_seq <= self.last_delivered + WATERMARK_WINDOW
    }

    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        let mut actions = Vec::new();
        match event {
            Event::PrePrepare(batch) => self.handle_pre_prepare(batch, &mut actions),
            Event::PayloadReady(batch) => self.handle_payload_ready(batch, &mut actions),
            Event::Vote(vote) => self.handle_vote(vote, &mut actions),
            Event::FastCommit(cert) => self.handle_fast_commit(cert, &mut actions),
            Event::ViewChange(vc) => self.handle_view_change(vc, &mut actions),
            Event::NewView(nv) => self.handle_new_view(nv, &mut actions),
            Event::TimerFired { view } => self.handle_timer(view, &mut actions),
            Event::SlowTimerFired { view, seq } => {
                self.handle_slow_timer(view, seq, &mut actions)
            }
            Event::Propose { payload } => self.handle_propose(payload, &mut actions),
            Event::SyncRequest {
                from,
                to,
                requester,
            } => self.handle_sync_request(from, to, requester, &mut actions),
            Event::SyncCert(cert) => self.handle_sync_cert(cert, &mut actions),
            Event::SyncRetryTick => {
                if let Some((from, to)) = self.outstanding_sync {
                    self.send_sync_request(from, to, &mut actions);
                }
            }
        }
        actions
    }

    // -- Normal case --

    fn handle_propose(&mut self, payload: Vec<Digest>, actions: &mut Vec<Action>) {
        if !self.want_proposal() {
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        actions.push(Action::SignPrePrepare {
            view: self.view,
            seq,
            payload,
        });
    }

    /// Laggard detection from traffic beyond the watermark window. A
    /// message for a sequence past `last_delivered + WATERMARK_WINDOW` is
    /// dropped by the normal handlers, so a replica that falls a full
    /// window behind (or is stuck ViewChanging while the quorum runs
    /// ahead) would otherwise discard the very evidence that it needs to
    /// catch up. Once f+1 distinct authors have been seen operating beyond
    /// our horizon, at least one correct replica is there, so the quorum
    /// has moved on without us: request certificate sync (the state
    /// transfer jump in handle_sync_cert covers ranges peers have already
    /// garbage-collected). Called before any view/status gating.
    fn note_quorum_progress(&mut self, author: PublicKey, seq: Seq, actions: &mut Vec<Action>) {
        let horizon = self.last_delivered + WATERMARK_WINDOW;
        if seq <= horizon || author == self.name {
            return;
        }
        self.beyond_window.insert(author, seq);
        self.beyond_window.retain(|_, s| *s > horizon);
        if self.beyond_window.len() >= self.committee.join_threshold() {
            let to = *self.beyond_window.values().min().unwrap();
            warn!(
                "{} replicas active beyond our watermark window (>= seq {}, last delivered {}); requesting catch-up sync",
                self.beyond_window.len(),
                to,
                self.last_delivered
            );
            self.beyond_window.clear();
            self.request_sync(self.last_delivered + 1, to, actions);
        }
    }

    fn handle_pre_prepare(&mut self, batch: Batch, actions: &mut Vec<Action>) {
        self.note_quorum_progress(batch.author, batch.seq, actions);
        if batch.view != self.view || self.status != Status::Active {
            debug!(
                "Ignoring pre-prepare for view {} (current {}, {:?})",
                batch.view, self.view, self.status
            );
            return;
        }
        if batch.author != self.committee.leader(batch.view) {
            warn!("Pre-prepare from non-leader {}", batch.author);
            return;
        }
        if batch.seq <= self.last_delivered
            || batch.seq > self.last_delivered + WATERMARK_WINDOW
        {
            debug!("Pre-prepare seq {} outside window", batch.seq);
            return;
        }
        let entry = self.entries.entry(batch.seq).or_default();
        if let Some(existing) = &entry.batch {
            if existing.view >= batch.view {
                return;
            }
        }
        if entry.awaiting_payload == Some(batch.view) {
            return;
        }
        entry.awaiting_payload = Some(batch.view);
        actions.push(Action::VerifyPayload(batch));
    }

    fn handle_payload_ready(&mut self, batch: Batch, actions: &mut Vec<Action>) {
        // Re-validate: a view change may have happened while syncing.
        if batch.view != self.view || self.status != Status::Active {
            return;
        }
        if batch.seq <= self.last_delivered {
            return;
        }
        let view = self.view;
        let digest = batch.content_digest();
        let seq = batch.seq;
        let entry = self.entries.entry(seq).or_default();
        entry.awaiting_payload = None;
        if let Some(existing) = &entry.batch {
            if existing.view >= batch.view {
                return;
            }
        }
        entry.batch = Some(batch);
        // Accepting a batch from a newer view invalidates prepared/committed
        // flags computed against an older one.
        entry.prepared = false;
        entry.committed = entry.cert.is_some();

        // Fast path: sign-share to the collector and start the slow-path
        // fallback timer.
        if entry.we_shared.insert(view) {
            actions.push(Action::SignShare {
                view,
                seq,
                digest,
            });
            actions.push(Action::ArmSlowTimer { view, seq });
        }
        self.evaluate_entry(seq, actions);
    }

    fn handle_vote(&mut self, vote: Vote, actions: &mut Vec<Action>) {
        self.note_quorum_progress(vote.author, vote.seq, actions);
        if vote.seq <= self.last_delivered {
            // A vote for a delivered sequence is the trace a laggard leaves
            // (e.g. after a dropped fast proof): hand it the certificate.
            if vote.author != self.name {
                if let Some(cert) = self.delivered_certs.get(&vote.seq) {
                    actions.push(Action::Send(
                        vote.author,
                        SbftMessage::SyncReply(vec![cert.clone()]),
                    ));
                }
            }
            return;
        }
        if vote.view != self.view {
            // Votes for other views are only useful for the view they were
            // cast in; old ones are stale and future ones will be re-cast
            // after the corresponding new-view.
            return;
        }
        if vote.seq > self.last_delivered + WATERMARK_WINDOW {
            return;
        }
        let seq = vote.seq;
        let phase = vote.phase;
        let entry = self.entries.entry(seq).or_default();
        entry
            .votes
            .insert((vote.view, vote.phase, vote.author), vote);

        // Any prepare vote joins us to the slow path for this seq: the
        // sender's slow-path timer fired, ours would too.
        if phase == Phase::Prepare && !entry.committed {
            if let Some(batch) = &entry.batch {
                if batch.view == self.view {
                    let digest = batch.content_digest();
                    if entry.we_prepared.insert(self.view) {
                        actions.push(Action::SignVote {
                            phase: Phase::Prepare,
                            view: self.view,
                            seq,
                            digest,
                        });
                    }
                }
            }
        }
        self.evaluate_entry(seq, actions);
    }

    fn handle_slow_timer(&mut self, view: View, seq: Seq, actions: &mut Vec<Action>) {
        if view != self.view || self.status != Status::Active {
            return; // Stale timer from before a view change.
        }
        if seq <= self.last_delivered {
            return;
        }
        let entry = match self.entries.get_mut(&seq) {
            Some(entry) => entry,
            None => return,
        };
        if entry.committed {
            return;
        }
        let digest = match &entry.batch {
            Some(batch) if batch.view == view => batch.content_digest(),
            _ => return,
        };
        if entry.we_prepared.insert(view) {
            info!("Fast path timed out for seq {}; falling back to slow path", seq);
            actions.push(Action::SignVote {
                phase: Phase::Prepare,
                view,
                seq,
                digest,
            });
        }
    }

    /// Re-evaluate the fast path (collector), prepared, and committed states
    /// for one sequence and cascade delivery.
    fn evaluate_entry(&mut self, seq: Seq, actions: &mut Vec<Action>) {
        let view = self.view;
        let quorum = self.committee.quorum_threshold();
        let fast = self.committee.fast_threshold();
        let we_are_collector = self.committee.leader(view) == self.name;

        let entry = match self.entries.get_mut(&seq) {
            Some(entry) => entry,
            None => return,
        };
        let (digest, batch_view, payload) = match &entry.batch {
            Some(batch) if batch.view == view => {
                (batch.content_digest(), batch.view, batch.payload.clone())
            }
            _ => return,
        };

        let collect = |entry: &Entry, phase: Phase| -> Vec<Vote> {
            entry
                .votes
                .iter()
                .filter(|((v, p, _), vote)| {
                    *v == batch_view && *p == phase && vote.digest == digest
                })
                .map(|(_, vote)| vote.clone())
                .collect()
        };

        // Collector: a share from every replica aggregates into the fast
        // commit proof.
        if we_are_collector && !entry.committed && !entry.fast_built.contains(&view) {
            let shares = collect(entry, Phase::SignShare);
            if shares.len() >= fast {
                entry.fast_built.insert(view);
                info!("Fast path complete for seq {}; broadcasting commit proof", seq);
                actions.push(Action::BroadcastFastCommit(CommitCert {
                    seq,
                    payload: payload.clone(),
                    commits: shares,
                }));
            }
        }

        // Slow path, exactly as PBFT.
        if !entry.prepared && collect(entry, Phase::Prepare).len() >= quorum {
            entry.prepared = true;
            if entry.we_committed.insert(view) {
                actions.push(Action::SignVote {
                    phase: Phase::Commit,
                    view,
                    seq,
                    digest: digest.clone(),
                });
            }
        }

        if !entry.committed {
            let commits = collect(entry, Phase::Commit);
            if commits.len() >= quorum {
                entry.committed = true;
                entry.cert = Some(CommitCert {
                    seq,
                    payload,
                    commits,
                });
            }
        }

        self.try_deliver(actions);
    }

    /// A verified commit proof (fast or slow) arrived from the network.
    fn handle_fast_commit(&mut self, cert: CommitCert, actions: &mut Vec<Action>) {
        if cert.seq > self.last_delivered + WATERMARK_WINDOW {
            // A valid commit certificate beyond our window is direct proof
            // the quorum has moved on without us (no f+1 counting needed:
            // the engine verified its signatures): request catch-up sync
            // for the whole gap rather than dropping it.
            self.request_sync(self.last_delivered + 1, cert.seq, actions);
            return;
        }
        if cert.seq <= self.last_delivered {
            return;
        }
        let entry = self.entries.entry(cert.seq).or_default();
        if entry.committed {
            return;
        }
        entry.committed = true;
        entry.cert = Some(cert);
        self.try_deliver(actions);
    }

    fn try_deliver(&mut self, actions: &mut Vec<Action>) {
        loop {
            let next = self.last_delivered + 1;
            let deliverable = match self.entries.get(&next) {
                Some(entry) => {
                    entry.committed && (entry.batch.is_some() || entry.cert.is_some())
                }
                None => false,
            };
            if !deliverable {
                break;
            }
            let entry = self.entries.remove(&next).unwrap();
            let fast = entry.cert.as_ref().map(|c| c.is_fast()).unwrap_or(false);
            // Prefer the batch for delivery metadata; a commit proof can
            // stand in when the pre-prepare never arrived (sync-style paths).
            let (view, leader, payload) = match &entry.batch {
                Some(batch) => (batch.view, batch.author, batch.payload.clone()),
                None => {
                    let cert = entry.cert.as_ref().unwrap();
                    let view = cert.commits.first().map(|v| v.view).unwrap_or(self.view);
                    (view, self.committee.leader(view), cert.payload.clone())
                }
            };
            info!(
                "Committed B{}({}) via {} path",
                next,
                base64::encode(content_digest(&payload)),
                if fast { "fast" } else { "slow" }
            );
            actions.push(Action::Deliver {
                seq: next,
                view,
                leader,
                payload: payload.clone(),
            });
            actions.push(Action::CleanupMempool {
                digests: payload,
                seq: next,
            });
            if let Some(cert) = entry.cert {
                self.delivered_certs.insert(next, cert);
            }
            self.last_delivered = next;
            self.delivered_since_timer = true;
            self.outstanding_sync = None;

            // Progress resets the election timer and its backoff.
            self.timer_factor = 0;
            self.timer_view = self.view;
            actions.push(Action::ArmTimer {
                view: self.view,
                factor: 0,
            });
        }

        // Garbage collection.
        let cutoff = self.last_delivered.saturating_sub(self.gc_depth);
        self.delivered_certs = self.delivered_certs.split_off(&cutoff);
        let stale: Vec<Seq> = self
            .entries
            .range(..=self.last_delivered)
            .map(|(s, _)| *s)
            .collect();
        for seq in stale {
            self.entries.remove(&seq);
        }
        let vc_cutoff = self.view;
        self.view_changes = self.view_changes.split_off(&vc_cutoff);

        // Detect a committed-but-undeliverable gap: something far ahead
        // committed while an earlier seq is missing entirely.
        if let Some((max_committed, _)) = self
            .entries
            .iter()
            .rev()
            .find(|(_, e)| e.committed)
        {
            let next = self.last_delivered + 1;
            let missing_next = self
                .entries
                .get(&next)
                .map(|e| e.batch.is_none() && e.awaiting_payload.is_none())
                .unwrap_or(true);
            if *max_committed > next && missing_next {
                self.request_sync(next, *max_committed - 1, actions);
            }
        }
    }

    fn request_sync(&mut self, from: Seq, to: Seq, actions: &mut Vec<Action>) {
        if self.outstanding_sync == Some((from, to)) {
            // Already requested; the engine's SyncRetryTick re-sends it.
            return;
        }
        self.outstanding_sync = Some((from, to));
        self.send_sync_request(from, to, actions);
    }

    fn send_sync_request(&mut self, from: Seq, to: Seq, actions: &mut Vec<Action>) {
        // Ask the current leader; retries naturally re-target after view
        // changes.
        let target = self.current_leader();
        let target = if target == self.name {
            // We are the leader; ask any other replica.
            match self
                .committee
                .sorted_names()
                .into_iter()
                .find(|n| *n != self.name)
            {
                Some(n) => n,
                None => return,
            }
        } else {
            target
        };
        debug!("Requesting decision sync [{}, {}] from {}", from, to, target);
        actions.push(Action::Send(
            target,
            SbftMessage::SyncRequest {
                from,
                to,
                requester: self.name,
            },
        ));
    }

    fn handle_sync_request(
        &mut self,
        from: Seq,
        to: Seq,
        requester: PublicKey,
        actions: &mut Vec<Action>,
    ) {
        if !self.committee.exists(&requester) || requester == self.name {
            return;
        }
        let certs: Vec<CommitCert> = self
            .delivered_certs
            .range(from..=to)
            .take(SYNC_REPLY_LIMIT)
            .map(|(_, cert)| cert.clone())
            .collect();
        if !certs.is_empty() {
            actions.push(Action::Send(requester, SbftMessage::SyncReply(certs)));
        }
    }

    fn handle_sync_cert(&mut self, cert: CommitCert, actions: &mut Vec<Action>) {
        if cert.seq <= self.last_delivered {
            return;
        }
        if cert.seq != self.last_delivered + 1 {
            // The certificates below this one were garbage-collected at
            // every reachable peer: without a state-transfer jump we would
            // be wedged forever (and with us, possibly the quorum). The
            // certificate is a valid commit proof, so jumping to it is
            // safe; the skipped sequences are simply not delivered locally.
            warn!(
                "State-transfer jump: skipping seqs {}..{} (certificates no longer retained by peers)",
                self.last_delivered + 1,
                cert.seq - 1
            );
        }
        let seq = cert.seq;
        let stale: Vec<Seq> = self.entries.range(..seq).map(|(s, _)| *s).collect();
        for s in stale {
            self.entries.remove(&s);
        }
        let fast = cert.is_fast();
        let view = cert.commits.first().map(|v| v.view).unwrap_or(self.view);
        let leader = self.committee.leader(view);
        info!(
            "Committed B{}({}) via {} path (synced)",
            seq,
            base64::encode(content_digest(&cert.payload)),
            if fast { "fast" } else { "slow" }
        );
        actions.push(Action::Deliver {
            seq,
            view,
            leader,
            payload: cert.payload.clone(),
        });
        actions.push(Action::CleanupMempool {
            digests: cert.payload.clone(),
            seq,
        });
        self.delivered_certs.insert(seq, cert);
        self.entries.remove(&seq);
        self.last_delivered = seq;
        self.delivered_since_timer = true;
        self.outstanding_sync = None;
        self.timer_factor = 0;
        self.timer_view = self.view;
        actions.push(Action::ArmTimer {
            view: self.view,
            factor: 0,
        });
        // Later sequences may already be committed locally.
        self.try_deliver(actions);
    }

    // -- View changes --

    fn handle_timer(&mut self, view: View, actions: &mut Vec<Action>) {
        if view != self.timer_view {
            return; // Stale timer.
        }
        let no_progress = !self.delivered_since_timer;
        actions.push(Action::RecordViewChange { no_progress });
        self.delivered_since_timer = false;

        let target = match self.status {
            Status::Active => self.view + 1,
            Status::ViewChanging { target } => target + 1,
        };
        warn!(
            "Election timeout in view {} ({:?}); moving to view change for view {}",
            self.view, self.status, target
        );
        self.timer_factor = self.timer_factor.saturating_add(1).min(6);
        self.start_view_change(target, actions);
    }

    fn start_view_change(&mut self, target: View, actions: &mut Vec<Action>) {
        self.status = Status::ViewChanging { target };
        self.timer_view = target;
        actions.push(Action::ArmTimer {
            view: target,
            factor: self.timer_factor,
        });

        let prepared = self.collect_prepared_certs();
        let shares = self.collect_own_shares();
        actions.push(Action::SignViewChange {
            view: target,
            last_delivered: self.last_delivered,
            prepared,
            shares,
        });
    }

    fn collect_prepared_certs(&self) -> Vec<PreparedCert> {
        let quorum = self.committee.quorum_threshold();
        let mut certs = Vec::new();
        for (_, entry) in self.entries.range(self.last_delivered + 1..) {
            let batch = match &entry.batch {
                Some(batch) => batch,
                None => continue,
            };
            if !entry.prepared {
                continue;
            }
            let digest = batch.content_digest();
            let prepares: Vec<Vote> = entry
                .votes
                .iter()
                .filter(|((v, p, _), vote)| {
                    *v == batch.view && *p == Phase::Prepare && vote.digest == digest
                })
                .map(|(_, vote)| vote.clone())
                .take(quorum)
                .collect();
            if prepares.len() >= quorum {
                certs.push(PreparedCert {
                    batch: batch.clone(),
                    prepares,
                });
            }
        }
        certs
    }

    /// Our own sign-share per undelivered sequence, as fast-path evidence.
    fn collect_own_shares(&self) -> Vec<ShareEvidence> {
        let mut shares = Vec::new();
        for (_, entry) in self.entries.range(self.last_delivered + 1..) {
            let batch = match &entry.batch {
                Some(batch) => batch,
                None => continue,
            };
            if let Some(share) = entry
                .votes
                .get(&(batch.view, Phase::SignShare, self.name))
            {
                shares.push(ShareEvidence {
                    batch: batch.clone(),
                    share: share.clone(),
                });
            }
        }
        shares
    }

    fn handle_view_change(&mut self, vc: ViewChangeMsg, actions: &mut Vec<Action>) {
        // A view-change reaching us while we are Active and delivering is a
        // false-positive timeout at the sender (or a laggard that missed
        // new-views entirely). Alone it can never gather f+1 view-changes,
        // and while ViewChanging it drops all current-view traffic, so
        // without help it is wedged for good. Hand it the new-view that
        // established our current view: handle_new_view accepts it while
        // not Active and returns the sender to this view. Only replied when
        // we have seen a delivery since our own timer was armed, so a dead
        // leader (where every replica times out) still elects normally.
        // (A Byzantine new leader could later replay the sender's now-stale
        // view-change signature; Byzantine replicas are out of scope for
        // this research platform.)
        if vc.author != self.name && self.status == Status::Active && self.delivered_since_timer {
            if let Some(nv) = &self.last_new_view {
                debug!(
                    "Re-sending new-view for view {} to view-changing {}",
                    nv.view, vc.author
                );
                actions.push(Action::Send(vc.author, SbftMessage::NewView(nv.clone())));
            }
        }
        if vc.view <= self.view {
            return;
        }
        self.view_changes
            .entry(vc.view)
            .or_default()
            .insert(vc.author, vc.clone());

        // Join rule (Castro-Liskov): if f+1 distinct replicas sent
        // view-changes for views beyond our current target - not necessarily
        // the SAME view - join the smallest of those views. Counting per
        // view would let independently escalating targets stay disjoint
        // forever and never re-converge into a quorum.
        let join = self.committee.join_threshold();
        let current_target = match self.status {
            Status::Active => self.view,
            Status::ViewChanging { target } => target,
        };
        let mut higher_authors: HashSet<PublicKey> = HashSet::new();
        let mut smallest_higher: Option<View> = None;
        for (v, msgs) in self.view_changes.range(current_target + 1..) {
            if smallest_higher.is_none() {
                smallest_higher = Some(*v);
            }
            higher_authors.extend(msgs.keys().copied());
        }
        if let Some(v) = smallest_higher {
            if higher_authors.len() >= join {
                info!("Joining view change for view {} (f+1 rule)", v);
                self.start_view_change(v, actions);
            }
        }

        self.maybe_build_new_view(vc.view, actions);
    }

    fn maybe_build_new_view(&mut self, view: View, actions: &mut Vec<Action>) {
        if self.committee.leader(view) != self.name
            || view <= self.view
            || self.new_view_built.contains(&view)
        {
            return;
        }
        let msgs = match self.view_changes.get(&view) {
            Some(msgs) => msgs,
            None => return,
        };
        if msgs.len() < self.committee.quorum_threshold() {
            return;
        }
        let view_changes: Vec<ViewChangeMsg> = msgs.values().cloned().collect();
        let o_payloads =
            Self::select_new_view_payloads(&view_changes, self.committee.join_threshold());
        self.new_view_built.insert(view);
        info!(
            "Building new-view for view {} ({} re-proposals)",
            view,
            o_payloads.len()
        );
        actions.push(Action::SignNewView {
            view,
            view_changes,
            o_payloads,
        });
    }

    /// The O-set: for each sequence between the highest delivered sequence
    /// among the view changes and the highest evidenced sequence, re-propose
    /// the winning candidate's payload, or an empty batch to fill the gap.
    /// Candidates per sequence: slow-path prepared certificates, and values
    /// with sign-shares from at least f+1 distinct view-change senders (a
    /// fast-committed value always qualifies: all correct replicas signed
    /// it, and no conflicting value can reach f+1 because conflicting shares
    /// would all be byzantine). The winner is the highest-view candidate; on
    /// a view tie a prepared certificate beats shares (a slow commit leaves
    /// a certificate in every view-change quorum), and remaining ties break
    /// on the content digest. Deterministic, so followers recompute and
    /// compare.
    pub(crate) fn select_new_view_payloads(
        view_changes: &[ViewChangeMsg],
        join_threshold: usize,
    ) -> Vec<(Seq, Vec<Digest>)> {
        let start = view_changes
            .iter()
            .map(|vc| vc.last_delivered)
            .max()
            .unwrap_or(0);

        // Candidate key: (view, is_cert, content digest). The winner per seq
        // is the maximum key.
        let mut best: BTreeMap<Seq, ((View, bool, [u8; 32]), Vec<Digest>)> = BTreeMap::new();
        let mut consider =
            |seq: Seq, view: View, is_cert: bool, digest: Digest, payload: &Vec<Digest>| {
                if seq <= start {
                    return;
                }
                let key = (view, is_cert, digest.0);
                match best.get(&seq) {
                    Some((existing, _)) if *existing >= key => {}
                    _ => {
                        best.insert(seq, (key, payload.clone()));
                    }
                }
            };

        for vc in view_changes {
            for cert in &vc.prepared {
                consider(
                    cert.batch.seq,
                    cert.batch.view,
                    true,
                    cert.batch.content_digest(),
                    &cert.batch.payload,
                );
            }
        }

        // Group share evidence by (seq, view, digest) and count distinct
        // view-change senders.
        let mut groups: HashMap<(Seq, View, [u8; 32]), (HashSet<PublicKey>, Vec<Digest>)> =
            HashMap::new();
        for vc in view_changes {
            for evidence in &vc.shares {
                let key = (
                    evidence.batch.seq,
                    evidence.batch.view,
                    evidence.batch.content_digest().0,
                );
                let (authors, _) = groups
                    .entry(key)
                    .or_insert_with(|| (HashSet::new(), evidence.batch.payload.clone()));
                authors.insert(vc.author);
            }
        }
        for ((seq, view, digest), (authors, payload)) in &groups {
            if authors.len() >= join_threshold {
                consider(*seq, *view, false, Digest(*digest), payload);
            }
        }

        let end = best.keys().next_back().copied().unwrap_or(start);
        (start + 1..=end)
            .map(|seq| {
                let payload = best
                    .get(&seq)
                    .map(|(_, payload)| payload.clone())
                    .unwrap_or_default();
                (seq, payload)
            })
            .collect()
    }

    fn handle_new_view(&mut self, nv: NewViewMsg, actions: &mut Vec<Action>) {
        if nv.view < self.view || (nv.view == self.view && self.status == Status::Active) {
            return;
        }

        // Validate the selection logic against our own recomputation.
        let expected =
            Self::select_new_view_payloads(&nv.view_changes, self.committee.join_threshold());
        let got: Vec<(Seq, Digest)> = nv
            .pre_prepares
            .iter()
            .map(|b| (b.seq, b.content_digest()))
            .collect();
        let expected_digests: Vec<(Seq, Digest)> = expected
            .iter()
            .map(|(seq, payload)| (*seq, content_digest(payload)))
            .collect();
        if got != expected_digests {
            warn!("Rejecting new-view for view {}: selection mismatch", nv.view);
            return;
        }

        info!(
            "Entering view {} via new-view from {} ({} re-proposals)",
            nv.view,
            nv.author,
            nv.pre_prepares.len()
        );
        self.last_new_view = Some(nv.clone());
        self.view = nv.view;
        self.status = Status::Active;
        self.timer_view = nv.view;
        actions.push(Action::ArmTimer {
            view: nv.view,
            factor: self.timer_factor,
        });

        // Entries above last_delivered restart in the new view: batches and
        // votes from older views are void (surviving content is re-proposed).
        for (_, entry) in self.entries.range_mut(self.last_delivered + 1..) {
            if entry.cert.is_none() {
                entry.batch = None;
                entry.awaiting_payload = None;
                entry.prepared = false;
                entry.committed = false;
            }
        }

        // Leader bookkeeping: continue assigning after the O-set.
        let max_o = nv.pre_prepares.iter().map(|b| b.seq).max();
        let start = nv
            .view_changes
            .iter()
            .map(|vc| vc.last_delivered)
            .max()
            .unwrap_or(0);
        self.next_seq = max_o.unwrap_or(start).max(self.last_delivered) + 1;

        // If the new view starts beyond our delivery point we are a laggard.
        if start > self.last_delivered {
            self.request_sync(self.last_delivered + 1, start, actions);
        }

        // Process the re-proposals like ordinary pre-prepares.
        for batch in nv.pre_prepares {
            self.handle_pre_prepare(batch, actions);
        }
    }
}
