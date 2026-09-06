//! The PBFT replica state machine, written sans-IO: every transition is a
//! pure function from (state, event) to (state, actions). All networking,
//! signing, clocks, and storage live in the engine (engine.rs); this module
//! can be driven deterministically in tests, which is what makes the
//! election logic testable before it ever reaches a real network.
//!
//! Protocol shape:
//! - Three phases per sequence (pre-prepare, prepare, commit) with uniform
//!   2f+1 quorums counting the sender's own vote.
//! - The leader pipelines sequences inside a watermark window and paces
//!   empty heartbeat batches, so a slow or censoring leader is always
//!   visible as a delivery gap.
//! - The single election timer re-arms on every delivery; firing starts a
//!   view change to view+1 (or target+1 if one is already in progress) with
//!   exponential backoff on consecutive failures.
//! - View changes carry prepared certificates; the new leader re-proposes
//!   the highest prepared content per sequence and fills gaps with empty
//!   batches; f+1 view changes for a higher view make a replica join.
//! - Laggards catch up via commit-certificate sync.

use crate::config::Committee;
use crate::messages::{
    content_digest, Batch, CommitCert, NewViewMsg, PbftMessage, Phase, PreparedCert, Seq, View,
    ViewChangeMsg, Vote,
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
    Vote(Vote),
    ViewChange(ViewChangeMsg),
    NewView(NewViewMsg),
    /// A batch previously deferred for payload sync is now fully available.
    PayloadReady(Batch),
    /// The election timer armed for `view` fired.
    TimerFired { view: View },
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
    /// Sign a vote, broadcast it, and feed it back in as Event::Vote.
    SignVote {
        phase: Phase,
        view: View,
        seq: Seq,
        digest: Digest,
    },
    /// Sign a view-change message, broadcast, feed back as Event::ViewChange.
    SignViewChange {
        view: View,
        last_delivered: Seq,
        prepared: Vec<PreparedCert>,
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
    /// timeout_cell * 2^factor.
    ArmTimer { view: View, factor: u32 },
    /// A genuine election timeout fired (for the learning window).
    RecordViewChange { no_progress: bool },
    Send(PublicKey, PbftMessage),
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
    votes: HashMap<(View, Phase, PublicKey), Vote>,
    prepared: bool,
    committed: bool,
    /// Views in which we already signed a prepare / commit for this seq.
    we_prepared: HashSet<View>,
    we_committed: HashSet<View>,
    /// Commit certificate, built when the seq commits.
    cert: Option<CommitCert>,
}

pub struct Pbft {
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

    /// The view the currently armed timer belongs to.
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

impl Pbft {
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
            Event::ViewChange(vc) => self.handle_view_change(vc, &mut actions),
            Event::NewView(nv) => self.handle_new_view(nv, &mut actions),
            Event::TimerFired { view } => self.handle_timer(view, &mut actions),
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

        if entry.we_prepared.insert(view) {
            actions.push(Action::SignVote {
                phase: Phase::Prepare,
                view,
                seq,
                digest,
            });
        }
        self.evaluate_entry(seq, actions);
    }

    fn handle_vote(&mut self, vote: Vote, actions: &mut Vec<Action>) {
        self.note_quorum_progress(vote.author, vote.seq, actions);
        if vote.view != self.view {
            // Votes for other views are only useful for the view they were
            // cast in; old ones are stale and future ones will be re-cast
            // after the corresponding new-view.
            return;
        }
        if vote.seq <= self.last_delivered
            || vote.seq > self.last_delivered + WATERMARK_WINDOW
        {
            return;
        }
        let entry = self.entries.entry(vote.seq).or_default();
        entry
            .votes
            .insert((vote.view, vote.phase, vote.author), vote.clone());
        self.evaluate_entry(vote.seq, actions);
    }

    /// Re-evaluate prepared/committed for one sequence and cascade delivery.
    fn evaluate_entry(&mut self, seq: Seq, actions: &mut Vec<Action>) {
        let view = self.view;
        let quorum = self.committee.quorum_threshold();
        let name = self.name;

        let entry = match self.entries.get_mut(&seq) {
            Some(entry) => entry,
            None => return,
        };
        let (digest, batch_view) = match &entry.batch {
            Some(batch) if batch.view == view => (batch.content_digest(), batch.view),
            _ => return,
        };

        let count = |entry: &Entry, phase: Phase| {
            let digest = &digest;
            entry
                .votes
                .iter()
                .filter(|((v, p, _), vote)| {
                    *v == batch_view && *p == phase && vote.digest == *digest
                })
                .count()
        };

        if !entry.prepared && count(entry, Phase::Prepare) >= quorum {
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

        if !entry.committed && count(entry, Phase::Commit) >= quorum {
            entry.committed = true;
            let commits: Vec<Vote> = entry
                .votes
                .iter()
                .filter(|((v, p, _), vote)| {
                    *v == batch_view && *p == Phase::Commit && vote.digest == digest
                })
                .map(|(_, vote)| vote.clone())
                .collect();
            let payload = entry.batch.as_ref().map(|b| b.payload.clone()).unwrap();
            entry.cert = Some(CommitCert {
                seq,
                payload,
                commits,
            });
            let _ = name;
        }

        self.try_deliver(actions);
    }

    fn try_deliver(&mut self, actions: &mut Vec<Action>) {
        loop {
            let next = self.last_delivered + 1;
            let deliverable = match self.entries.get(&next) {
                Some(entry) => entry.committed && entry.batch.is_some(),
                None => false,
            };
            if !deliverable {
                break;
            }
            let entry = self.entries.remove(&next).unwrap();
            let batch = entry.batch.unwrap();
            info!("Committed B{}({})", next, base64::encode(batch.content_digest()));
            actions.push(Action::Deliver {
                seq: next,
                view: batch.view,
                leader: batch.author,
                payload: batch.payload.clone(),
            });
            actions.push(Action::CleanupMempool {
                digests: batch.payload,
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
            PbftMessage::SyncRequest {
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
            actions.push(Action::Send(requester, PbftMessage::SyncReply(certs)));
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
        let leader = cert
            .commits
            .first()
            .map(|v| self.committee.leader(v.view))
            .unwrap_or(self.name);
        let view = cert.commits.first().map(|v| v.view).unwrap_or(self.view);
        info!("Committed B{}({})", seq, base64::encode(content_digest(&cert.payload)));
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
        actions.push(Action::SignViewChange {
            view: target,
            last_delivered: self.last_delivered,
            prepared,
        });
    }

    fn collect_prepared_certs(&self) -> Vec<PreparedCert> {
        let quorum = self.committee.quorum_threshold();
        let mut certs = Vec::new();
        for (seq, entry) in self.entries.range(self.last_delivered + 1..) {
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
            let _ = seq;
        }
        certs
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
                actions.push(Action::Send(vc.author, PbftMessage::NewView(nv.clone())));
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
        let o_payloads = Self::select_new_view_payloads(&view_changes);
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
    /// among the view changes and the highest prepared sequence, re-propose
    /// the payload of the highest-view prepared certificate, or an empty
    /// batch to fill the gap. Deterministic, so followers recompute and
    /// compare.
    fn select_new_view_payloads(view_changes: &[ViewChangeMsg]) -> Vec<(Seq, Vec<Digest>)> {
        let start = view_changes
            .iter()
            .map(|vc| vc.last_delivered)
            .max()
            .unwrap_or(0);
        let mut best: BTreeMap<Seq, (&PreparedCert, View)> = BTreeMap::new();
        for vc in view_changes {
            for cert in &vc.prepared {
                let seq = cert.batch.seq;
                if seq <= start {
                    continue;
                }
                let view = cert.batch.view;
                match best.get(&seq) {
                    Some((_, existing_view)) if *existing_view >= view => {}
                    _ => {
                        best.insert(seq, (cert, view));
                    }
                }
            }
        }
        let end = best.keys().next_back().copied().unwrap_or(start);
        (start + 1..=end)
            .map(|seq| {
                let payload = best
                    .get(&seq)
                    .map(|(cert, _)| cert.batch.payload.clone())
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
        let expected = Self::select_new_view_payloads(&nv.view_changes);
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
        // votes from older views are void (prepared content is re-proposed).
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
