//! Scripted-event tests: four real SBFT state machines driven
//! deterministically with manual message routing, partitions, targeted fast
//! proof drops, and explicit timer fires. No network, no clocks, no
//! signatures (the engine verifies those; the state machine treats them as
//! opaque).

use crate::config::Committee;
use crate::messages::{
    Batch, NewViewMsg, Phase, PreparedCert, SbftMessage, Seq, ShareEvidence, View,
    ViewChangeMsg, Vote,
};
use crate::state::{Action, Event, Sbft, WATERMARK_WINDOW};
use crypto::{generate_keypair, Digest, PublicKey, Signature as CryptoSignature};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use std::collections::{HashSet, VecDeque};

fn keys() -> Vec<(PublicKey, crypto::SecretKey)> {
    let mut rng = StdRng::from_seed([7; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

fn committee() -> Committee {
    Committee::new(
        keys()
            .into_iter()
            .enumerate()
            .map(|(i, (name, _))| (name, 1, format!("127.0.0.1:{}", 13000 + i).parse().unwrap()))
            .collect(),
        1,
    )
}

fn payload(tag: u8) -> Vec<Digest> {
    vec![Digest([tag; 32])]
}

struct Sim {
    committee: Committee,
    /// Replicas indexed in leader-schedule order (sorted names), so
    /// `nodes[v % 4]` is the leader/collector of view v.
    names: Vec<PublicKey>,
    nodes: Vec<Sbft>,
    inboxes: Vec<VecDeque<Event>>,
    delivered: Vec<Vec<(Seq, Vec<Digest>)>>,
    timers: Vec<Option<(View, u32)>>,
    slow_timers: Vec<Vec<(View, Seq)>>,
    recorded_view_changes: Vec<Vec<bool>>, // no_progress flags
    /// Nodes cut off from the network (their sends are dropped and they
    /// receive nothing; self-feedback still works, as in the engine).
    partitioned: HashSet<usize>,
    /// Nodes that do not receive broadcast fast commit proofs.
    drop_fast_commit_to: HashSet<usize>,
    /// Prepare votes put on the wire (zero on a pure fast path).
    prepare_votes_sent: usize,
}

impl Sim {
    fn new() -> Self {
        let committee = committee();
        let names = committee.sorted_names();
        let mut nodes = Vec::new();
        let mut timers = Vec::new();
        let mut inboxes = Vec::new();
        for name in &names {
            let (node, actions) = Sbft::new(*name, committee.clone(), 50);
            nodes.push(node);
            timers.push(None);
            inboxes.push(VecDeque::new());
            let idx = nodes.len() - 1;
            for action in actions {
                if let Action::ArmTimer { view, factor } = action {
                    timers[idx] = Some((view, factor));
                }
            }
        }
        Self {
            committee,
            names,
            nodes,
            inboxes,
            delivered: vec![Vec::new(); 4],
            timers,
            slow_timers: vec![Vec::new(); 4],
            recorded_view_changes: vec![Vec::new(); 4],
            partitioned: HashSet::new(),
            drop_fast_commit_to: HashSet::new(),
            prepare_votes_sent: 0,
        }
    }

    fn index_of(&self, name: &PublicKey) -> usize {
        self.names.iter().position(|n| n == name).unwrap()
    }

    fn leader_of(&self, view: View) -> usize {
        self.index_of(&self.committee.leader(view))
    }

    fn broadcast(&mut self, from: usize, make: impl Fn() -> Event) {
        for to in 0..self.nodes.len() {
            if to == from {
                // Self-feedback always works (engine feeds its own events).
                self.inboxes[to].push_back(make());
                continue;
            }
            if self.partitioned.contains(&from) || self.partitioned.contains(&to) {
                continue;
            }
            self.inboxes[to].push_back(make());
        }
    }

    fn handle_actions(&mut self, node: usize, actions: Vec<Action>) {
        let name = self.names[node];
        for action in actions {
            match action {
                Action::SignPrePrepare { view, seq, payload } => {
                    let batch = Batch {
                        view,
                        seq,
                        payload,
                        author: name,
                        signature: CryptoSignature::default(),
                    };
                    self.broadcast(node, || Event::PrePrepare(batch.clone()));
                }
                Action::SignShare { view, seq, digest } => {
                    let vote = Vote {
                        phase: Phase::SignShare,
                        view,
                        seq,
                        digest,
                        author: name,
                        signature: CryptoSignature::default(),
                    };
                    // Self-feedback always; the collector gets it over the
                    // wire unless a partition blocks it.
                    self.inboxes[node].push_back(Event::Vote(vote.clone()));
                    let collector = self.leader_of(view);
                    if collector != node
                        && !self.partitioned.contains(&node)
                        && !self.partitioned.contains(&collector)
                    {
                        self.inboxes[collector].push_back(Event::Vote(vote));
                    }
                }
                Action::SignVote {
                    phase,
                    view,
                    seq,
                    digest,
                } => {
                    if phase == Phase::Prepare {
                        self.prepare_votes_sent += 1;
                    }
                    let vote = Vote {
                        phase,
                        view,
                        seq,
                        digest,
                        author: name,
                        signature: CryptoSignature::default(),
                    };
                    self.broadcast(node, || Event::Vote(vote.clone()));
                }
                Action::BroadcastFastCommit(cert) => {
                    for to in 0..self.nodes.len() {
                        if to == node {
                            self.inboxes[to].push_back(Event::FastCommit(cert.clone()));
                            continue;
                        }
                        if self.partitioned.contains(&node)
                            || self.partitioned.contains(&to)
                            || self.drop_fast_commit_to.contains(&to)
                        {
                            continue;
                        }
                        self.inboxes[to].push_back(Event::FastCommit(cert.clone()));
                    }
                }
                Action::SignViewChange {
                    view,
                    last_delivered,
                    prepared,
                    shares,
                } => {
                    let vc = ViewChangeMsg {
                        view,
                        last_delivered,
                        prepared,
                        shares,
                        author: name,
                        signature: CryptoSignature::default(),
                    };
                    self.broadcast(node, || Event::ViewChange(vc.clone()));
                }
                Action::SignNewView {
                    view,
                    view_changes,
                    o_payloads,
                } => {
                    let pre_prepares: Vec<Batch> = o_payloads
                        .into_iter()
                        .map(|(seq, payload)| Batch {
                            view,
                            seq,
                            payload,
                            author: name,
                            signature: CryptoSignature::default(),
                        })
                        .collect();
                    let nv = NewViewMsg {
                        view,
                        view_changes,
                        pre_prepares,
                        author: name,
                        signature: CryptoSignature::default(),
                    };
                    self.broadcast(node, || Event::NewView(nv.clone()));
                }
                Action::VerifyPayload(batch) => {
                    // Payloads are always locally available in these tests.
                    self.inboxes[node].push_back(Event::PayloadReady(batch));
                }
                Action::Deliver { seq, payload, .. } => {
                    self.delivered[node].push((seq, payload));
                }
                Action::CleanupMempool { .. } => {}
                Action::ArmTimer { view, factor } => {
                    self.timers[node] = Some((view, factor));
                }
                Action::ArmSlowTimer { view, seq } => {
                    self.slow_timers[node].push((view, seq));
                }
                Action::RecordViewChange { no_progress } => {
                    self.recorded_view_changes[node].push(no_progress);
                }
                Action::Send(to, message) => {
                    let to_idx = self.index_of(&to);
                    if self.partitioned.contains(&node) || self.partitioned.contains(&to_idx) {
                        continue;
                    }
                    let events: Vec<Event> = match message {
                        SbftMessage::SyncRequest {
                            from,
                            to,
                            requester,
                        } => vec![Event::SyncRequest {
                            from,
                            to,
                            requester,
                        }],
                        SbftMessage::SyncReply(certs) => {
                            certs.into_iter().map(Event::SyncCert).collect()
                        }
                        SbftMessage::NewView(nv) => vec![Event::NewView(nv)],
                        other => panic!("unexpected direct message {:?}", other),
                    };
                    for event in events {
                        self.inboxes[to_idx].push_back(event);
                    }
                }
            }
        }
    }

    /// Process every queued event until quiescent.
    fn drain(&mut self) {
        loop {
            let Some(node) = (0..self.nodes.len()).find(|i| !self.inboxes[*i].is_empty()) else {
                return;
            };
            let event = self.inboxes[node].pop_front().unwrap();
            let actions = self.nodes[node].handle(event);
            self.handle_actions(node, actions);
        }
    }

    /// Leader of the current view (as seen by `node`) proposes a payload.
    fn propose(&mut self, node: usize, payload: Vec<Digest>) {
        assert!(self.nodes[node].want_proposal(), "node {} cannot propose", node);
        let actions = self.nodes[node].handle(Event::Propose { payload });
        self.handle_actions(node, actions);
        self.drain();
    }

    /// Fire the armed election timer on one node.
    fn fire_timer(&mut self, node: usize) {
        let (view, _) = self.timers[node].expect("no timer armed");
        let actions = self.nodes[node].handle(Event::TimerFired { view });
        self.handle_actions(node, actions);
    }

    /// Fire all armed slow-path timers on one node.
    fn fire_slow_timers(&mut self, node: usize) {
        let armed: Vec<(View, Seq)> = self.slow_timers[node].drain(..).collect();
        for (view, seq) in armed {
            let actions = self.nodes[node].handle(Event::SlowTimerFired { view, seq });
            self.handle_actions(node, actions);
        }
        self.drain();
    }
}

#[test]
fn fast_path_commits_without_prepare_votes() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    sim.propose(leader, payload(1));
    sim.propose(leader, payload(2));
    sim.propose(leader, payload(3));

    for node in 0..4 {
        assert_eq!(
            sim.delivered[node],
            vec![(1, payload(1)), (2, payload(2)), (3, payload(3))],
            "node {} delivery mismatch",
            node
        );
        assert!(sim.recorded_view_changes[node].is_empty());
        assert_eq!(sim.nodes[node].view(), 0);
    }
    assert_eq!(
        sim.prepare_votes_sent, 0,
        "the fast path must not put prepare votes on the wire"
    );
}

#[test]
fn pipelined_proposals_deliver_in_order() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    // Assign several sequences before draining anything: the leader may
    // pipeline inside the watermark window.
    for tag in 1..=5u8 {
        assert!(sim.nodes[leader].want_proposal());
        let actions = sim.nodes[leader].handle(Event::Propose {
            payload: payload(tag),
        });
        sim.handle_actions(leader, actions);
    }
    sim.drain();
    for node in 0..4 {
        let seqs: Vec<Seq> = sim.delivered[node].iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    }
    assert_eq!(sim.prepare_votes_sent, 0);
}

#[test]
fn crashed_replica_forces_slow_path() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    let crashed = (leader + 1) % 4;
    sim.partitioned.insert(crashed);

    // With one replica silent the collector never reaches all-n; nothing
    // delivers on the fast path.
    sim.propose(leader, payload(7));
    for node in 0..4 {
        assert!(sim.delivered[node].is_empty(), "node {} delivered early", node);
    }

    // The slow-path timers fire and the 2f+1 fallback commits.
    for node in 0..4 {
        if node != crashed {
            sim.fire_slow_timers(node);
        }
    }
    for node in 0..4 {
        if node == crashed {
            assert!(sim.delivered[node].is_empty());
            continue;
        }
        assert_eq!(
            sim.delivered[node],
            vec![(1, payload(7))],
            "node {} slow path failed",
            node
        );
        assert_eq!(sim.nodes[node].view(), 0, "slow path must not change views");
    }
    assert!(sim.prepare_votes_sent > 0);
}

#[test]
fn dropped_fast_proof_recovers_via_certificate_reply() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    let laggard = (leader + 1) % 4;
    sim.drop_fast_commit_to.insert(laggard);

    sim.propose(leader, payload(9));
    for node in 0..4 {
        if node == laggard {
            assert!(sim.delivered[node].is_empty());
        } else {
            assert_eq!(sim.delivered[node], vec![(1, payload(9))]);
        }
    }

    // The laggard's slow-path timer fires; its prepare vote for a delivered
    // sequence prompts a targeted certificate reply.
    sim.fire_slow_timers(laggard);
    assert_eq!(
        sim.delivered[laggard],
        vec![(1, payload(9))],
        "laggard failed to recover the dropped fast proof"
    );
}

#[test]
fn fast_committed_content_survives_view_change() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);

    // The collector's fast proof reaches nobody else: only the collector
    // delivers, everyone else holds a bare sign-share.
    for node in 0..4 {
        if node != leader {
            sim.drop_fast_commit_to.insert(node);
        }
    }
    sim.propose(leader, payload(42));
    assert_eq!(sim.delivered[leader], vec![(1, payload(42))]);
    for node in 0..4 {
        if node != leader {
            assert!(sim.delivered[node].is_empty());
        }
    }

    // The leader goes silent; the rest elect a new view. Their view changes
    // carry sign-shares only, and the f+1 share rule must force the new
    // leader to re-propose the fast-committed content.
    sim.partitioned.insert(leader);
    for node in 0..4 {
        if node != leader {
            sim.fire_timer(node);
        }
    }
    sim.drain();
    let new_leader = sim.leader_of(1);
    assert_ne!(new_leader, leader);
    for node in 0..4 {
        if node != leader {
            assert_eq!(sim.nodes[node].view(), 1, "node {} stuck", node);
        }
    }

    // The re-proposal cannot fast-commit (the old leader is gone), so the
    // slow path finishes it.
    for node in 0..4 {
        if node != leader {
            sim.fire_slow_timers(node);
        }
    }
    for node in 0..4 {
        if node == leader {
            continue;
        }
        assert_eq!(
            sim.delivered[node],
            vec![(1, payload(42))],
            "node {} lost fast-committed content across the view change",
            node
        );
    }
}

#[test]
fn selection_prefers_certificates_then_higher_view_shares() {
    let committee = committee();
    let names = committee.sorted_names();
    let make_batch = |view: View, tag: u8| Batch {
        view,
        seq: 1,
        payload: payload(tag),
        author: committee.leader(view),
        signature: CryptoSignature::default(),
    };
    let share = |batch: &Batch, author: PublicKey| Vote {
        phase: Phase::SignShare,
        view: batch.view,
        seq: batch.seq,
        digest: batch.content_digest(),
        author,
        signature: CryptoSignature::default(),
    };
    let prepare = |batch: &Batch, author: PublicKey| Vote {
        phase: Phase::Prepare,
        view: batch.view,
        seq: batch.seq,
        digest: batch.content_digest(),
        author,
        signature: CryptoSignature::default(),
    };
    let vc = |author: PublicKey, prepared: Vec<PreparedCert>, shares: Vec<ShareEvidence>| {
        ViewChangeMsg {
            view: 2,
            last_delivered: 0,
            prepared,
            shares,
            author,
            signature: CryptoSignature::default(),
        }
    };

    let x = make_batch(0, 1);
    let y = make_batch(0, 2);
    let cert_x = PreparedCert {
        batch: x.clone(),
        prepares: names.iter().take(3).map(|n| prepare(&x, *n)).collect(),
    };

    // Same view: a prepared certificate for X beats f+1 shares for Y.
    let vcs = vec![
        vc(names[0], vec![cert_x.clone()], vec![]),
        vc(
            names[1],
            vec![],
            vec![ShareEvidence {
                batch: y.clone(),
                share: share(&y, names[1]),
            }],
        ),
        vc(
            names[2],
            vec![],
            vec![ShareEvidence {
                batch: y.clone(),
                share: share(&y, names[2]),
            }],
        ),
    ];
    let selected = Sbft::select_new_view_payloads(&vcs, committee.join_threshold());
    assert_eq!(selected, vec![(1, payload(1))]);

    // Higher view: f+1 shares for Y in view 1 beat the view-0 certificate.
    let y1 = make_batch(1, 2);
    let vcs = vec![
        vc(names[0], vec![cert_x], vec![]),
        vc(
            names[1],
            vec![],
            vec![ShareEvidence {
                batch: y1.clone(),
                share: share(&y1, names[1]),
            }],
        ),
        vc(
            names[2],
            vec![],
            vec![ShareEvidence {
                batch: y1.clone(),
                share: share(&y1, names[2]),
            }],
        ),
    ];
    let selected = Sbft::select_new_view_payloads(&vcs, committee.join_threshold());
    assert_eq!(selected, vec![(1, payload(2))]);

    // Below f+1, shares are not a candidate: the certificate still wins.
    let vcs = vec![
        vc(
            names[0],
            vec![PreparedCert {
                batch: x.clone(),
                prepares: names.iter().take(3).map(|n| prepare(&x, *n)).collect(),
            }],
            vec![],
        ),
        vc(
            names[1],
            vec![],
            vec![ShareEvidence {
                batch: y1.clone(),
                share: share(&y1, names[1]),
            }],
        ),
        vc(names[2], vec![], vec![]),
    ];
    let selected = Sbft::select_new_view_payloads(&vcs, committee.join_threshold());
    assert_eq!(selected, vec![(1, payload(1))]);
}

#[test]
fn silent_leader_triggers_election_and_recovery() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);

    // The leader is cut off before proposing anything.
    sim.partitioned.insert(leader);

    // The three connected replicas time out.
    for node in 0..4 {
        if node != leader {
            sim.fire_timer(node);
        }
    }
    sim.drain();

    let new_leader = sim.leader_of(1);
    assert_ne!(new_leader, leader);
    for node in 0..4 {
        if node == leader {
            continue;
        }
        assert_eq!(sim.recorded_view_changes[node], vec![true]);
        assert_eq!(sim.nodes[node].view(), 1, "node {} stuck", node);
        assert!(sim.nodes[node].is_active());
    }

    // The new view makes progress with 2f+1 replicas via the slow path.
    sim.propose(new_leader, payload(9));
    for node in 0..4 {
        if node != leader {
            sim.fire_slow_timers(node);
        }
    }
    for node in 0..4 {
        if node == leader {
            continue;
        }
        assert_eq!(sim.delivered[node], vec![(1, payload(9))]);
    }
}

#[test]
fn f_plus_one_join_rule() {
    let mut sim = Sim::new();

    // Only two replicas (f+1) time out; the rest must join without firing
    // their own timers.
    let leader = sim.leader_of(0);
    let mut fired = 0;
    for node in 0..4 {
        if node != leader && fired < 2 {
            sim.fire_timer(node);
            fired += 1;
        }
    }
    sim.drain();

    for node in 0..4 {
        assert_eq!(sim.nodes[node].view(), 1, "node {} did not join", node);
        assert!(sim.nodes[node].is_active());
    }
}

#[test]
fn join_rule_converges_across_mixed_higher_views() {
    // Replicas whose view-change targets desynchronized (e.g. while peers
    // were unreachable) ask for DIFFERENT higher views. Castro-Liskov: f+1
    // distinct senders wanting any higher view make us join the smallest.
    let mut sim = Sim::new();
    let vc = |view: View, author: PublicKey| ViewChangeMsg {
        view,
        last_delivered: 0,
        prepared: Vec::new(),
        shares: Vec::new(),
        author,
        signature: CryptoSignature::default(),
    };

    // One replica asks for view 5: not enough on its own.
    let actions = sim.nodes[0].handle(Event::ViewChange(vc(5, sim.names[1])));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::SignViewChange { .. })),
        "joined a view change on a single message"
    );

    // A second replica asks for view 7: f+1 distinct senders now want out,
    // with no single view holding f+1. The node must join view 5.
    let actions = sim.nodes[0].handle(Event::ViewChange(vc(7, sim.names[2])));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::SignViewChange { view: 5, .. })),
        "did not join the smallest higher view"
    );
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::ArmTimer { view: 5, .. })));
}

#[test]
fn repeated_timeouts_backoff_and_flag_no_progress() {
    let mut sim = Sim::new();
    // Total partition: every node alone.
    sim.partitioned.extend(0..4);

    sim.fire_timer(1);
    sim.drain();
    let (view_a, factor_a) = sim.timers[1].unwrap();
    sim.fire_timer(1);
    sim.drain();
    let (view_b, factor_b) = sim.timers[1].unwrap();

    assert_eq!(sim.recorded_view_changes[1], vec![true, true]);
    assert!(view_b > view_a);
    assert!(factor_b > factor_a, "timer backoff must grow");
}

#[test]
fn pre_prepare_from_non_leader_is_ignored() {
    let mut sim = Sim::new();
    let non_leader = (sim.leader_of(0) + 1) % 4;
    let batch = Batch {
        view: 0,
        seq: 1,
        payload: payload(5),
        author: sim.names[non_leader],
        signature: CryptoSignature::default(),
    };
    for node in 0..4 {
        let actions = sim.nodes[node].handle(Event::PrePrepare(batch.clone()));
        assert!(
            actions.is_empty(),
            "node {} accepted a pre-prepare from a non-leader",
            node
        );
    }
}

#[test]
fn laggard_catches_up_via_commit_certificates() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    let laggard = (leader + 1) % 4;

    // Three sequences commit on the slow path while the laggard is cut off
    // (the fast path is impossible with a replica missing).
    sim.partitioned.insert(laggard);
    for tag in 1..=3u8 {
        sim.propose(leader, payload(tag));
    }
    for node in 0..4 {
        if node != laggard {
            sim.fire_slow_timers(node);
        }
    }
    assert!(sim.delivered[laggard].is_empty());
    for node in 0..4 {
        if node != laggard {
            let seqs: Vec<Seq> = sim.delivered[node].iter().map(|(s, _)| *s).collect();
            assert_eq!(seqs, vec![1, 2, 3]);
        }
    }

    // Heal; the next sequence fast-commits everywhere and exposes the gap.
    sim.partitioned.clear();
    sim.propose(leader, payload(4));
    sim.drain();

    let seqs: Vec<Seq> = sim.delivered[laggard].iter().map(|(s, _)| *s).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4], "laggard failed to catch up");
    for (i, (_, p)) in sim.delivered[laggard].iter().enumerate() {
        assert_eq!(*p, payload((i + 1) as u8));
    }
}

#[test]
fn laggard_beyond_cert_retention_jumps_forward() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    let laggard = (leader + 1) % 4;

    // 60 sequences commit on the slow path while the laggard is cut off;
    // with gc_depth 50 the peers retain certificates only for seqs 11..=60.
    sim.partitioned.insert(laggard);
    for i in 1..=60u64 {
        sim.propose(leader, payload((i % 250) as u8));
        for node in 0..4 {
            if node != laggard {
                sim.fire_slow_timers(node);
            }
        }
    }
    assert!(sim.delivered[laggard].is_empty());

    // Heal; the next sequence fast-commits everywhere, exposing the gap;
    // the laggard must jump over the garbage-collected prefix instead of
    // wedging.
    sim.partitioned.clear();
    sim.propose(leader, payload(61));
    sim.drain();

    let seqs: Vec<Seq> = sim.delivered[laggard].iter().map(|(s, _)| *s).collect();
    assert_eq!(
        seqs,
        (11..=61).collect::<Vec<_>>(),
        "laggard wedged instead of jumping over the collected prefix"
    );
}

#[test]
fn slow_leader_election_after_partial_progress() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);

    // Some fast-path progress first.
    sim.propose(leader, payload(1));

    // Then the leader goes silent and the rest elect a new one.
    sim.partitioned.insert(leader);
    for node in 0..4 {
        if node != leader {
            sim.fire_timer(node);
        }
    }
    sim.drain();

    let new_leader = sim.leader_of(1);
    sim.propose(new_leader, payload(2));
    for node in 0..4 {
        if node != leader {
            sim.fire_slow_timers(node);
        }
    }
    for node in 0..4 {
        if node == leader {
            continue;
        }
        assert_eq!(
            sim.delivered[node],
            vec![(1, payload(1)), (2, payload(2))],
            "node {} lost progress across the election",
            node
        );
        assert_eq!(sim.nodes[node].view(), 1);
    }
}

/// Run 20260905_234508 (pbft twin): a replica whose election timer fires
/// while the rest of the committee is healthy enters ViewChanging, where it
/// drops all current-view traffic; alone it can never gather f+1
/// view-changes, and a stable quorum never issues another new-view, so it
/// used to be wedged forever. Active replicas now answer its view-change by
/// re-sending the new-view that established the current view.
#[test]
fn lone_view_changer_rejoins_via_resent_new_view() {
    let mut sim = Sim::new();
    // Establish view 1 first: view 0 has no new-view message to re-send.
    for node in 0..4 {
        sim.fire_timer(node);
    }
    sim.drain();
    let leader = sim.leader_of(1);
    for node in 0..4 {
        assert_eq!(sim.nodes[node].view(), 1);
        assert!(sim.nodes[node].is_active());
    }

    sim.propose(leader, payload(1));

    // One replica times out alone (a false-positive election). The three
    // healthy replicas do not join (f+1 rule) but each hands it the view-1
    // new-view, returning it to Active in view 1.
    let straggler = (leader + 1) % 4;
    sim.fire_timer(straggler);
    assert!(!sim.nodes[straggler].is_active());
    sim.drain();
    assert!(
        sim.nodes[straggler].is_active(),
        "straggler still stuck in ViewChanging"
    );
    for node in 0..4 {
        assert_eq!(sim.nodes[node].view(), 1);
    }

    // Delivery continues everywhere, straggler included (all-n fast path
    // works again precisely because the straggler is back).
    sim.propose(leader, payload(2));
    for node in 0..4 {
        assert_eq!(
            sim.delivered[node],
            vec![(1, payload(1)), (2, payload(2))],
            "node {} delivery mismatch",
            node
        );
    }
}

/// A replica more than a full watermark window behind used to drop every
/// message from the live quorum (all sequences beyond its horizon) and so
/// never learned it had to sync. Traffic from f+1 distinct authors beyond
/// the window (or a single valid commit certificate) now triggers
/// certificate sync, and the state-transfer jump crosses the range peers
/// have already garbage-collected.
#[test]
fn straggler_beyond_window_syncs_from_quorum_traffic() {
    let mut sim = Sim::new();
    let leader = sim.leader_of(0);
    let straggler = (leader + 1) % 4;
    sim.partitioned.insert(straggler);

    // The quorum outruns the straggler by more than a window; with one
    // replica silent every sequence needs the slow path.
    for i in 0..(WATERMARK_WINDOW + 2) {
        sim.propose(leader, payload((i % 250) as u8 + 1));
        for node in 0..4 {
            if node != straggler {
                sim.fire_slow_timers(node);
            }
        }
    }
    assert_eq!(sim.nodes[straggler].last_delivered(), 0);
    assert!(sim.nodes[leader].last_delivered() > WATERMARK_WINDOW);

    // Reconnect: the next proposal's traffic is all beyond the straggler's
    // window (it cannot sign-share yet, so the seq still needs the slow
    // path at the live nodes).
    sim.partitioned.remove(&straggler);
    sim.propose(leader, payload(251));
    for node in 0..4 {
        if node != straggler {
            sim.fire_slow_timers(node);
        }
    }
    let retry = sim.nodes[straggler].handle(Event::SyncRetryTick);
    sim.handle_actions(straggler, retry);
    sim.drain();
    sim.propose(leader, payload(252));

    assert!(sim.nodes[straggler].last_delivered() >= WATERMARK_WINDOW);
    assert_eq!(
        sim.nodes[straggler].last_delivered(),
        sim.nodes[leader].last_delivered(),
        "straggler failed to catch up"
    );
}
