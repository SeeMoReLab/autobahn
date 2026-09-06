use crate::config::Committee;
use crate::error::{SbftError, SbftResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;

pub type View = u64;
pub type Seq = u64;

/// Digest binding only the payload content. Certificates and share evidence
/// bind this digest (with view and seq carried in the votes), so a new
/// leader can re-pre-prepare the same content in a later view and existing
/// certificates still refer to it.
pub fn content_digest(payload: &[Digest]) -> Digest {
    let mut hasher = Sha512::new();
    for x in payload {
        hasher.update(x);
    }
    Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
}

/// A pre-prepare: the view leader's batch proposal for one sequence number.
/// An empty payload is a heartbeat batch; the leader paces these even without
/// load so its liveness is always observable.
#[derive(Clone, Serialize, Deserialize)]
pub struct Batch {
    pub view: View,
    pub seq: Seq,
    pub payload: Vec<Digest>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Batch {
    pub async fn new(
        view: View,
        seq: Seq,
        payload: Vec<Digest>,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let batch = Self {
            view,
            seq,
            payload,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(batch.digest()).await;
        Self { signature, ..batch }
    }

    pub fn content_digest(&self) -> Digest {
        content_digest(&self.payload)
    }

    pub fn verify(&self, committee: &Committee) -> SbftResult<()> {
        ensure!(
            committee.exists(&self.author),
            SbftError::UnknownAuthority(self.author)
        );
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(SbftError::from)
    }
}

impl Hash for Batch {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.view.to_le_bytes());
        hasher.update(self.seq.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Batch {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "Batch(v{}, n{}, {} payloads, author {})",
            self.view,
            self.seq,
            self.payload.len(),
            self.author
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum Phase {
    /// Fast-path share, sent only to the collector (the view leader).
    SignShare,
    /// Slow-path phases, broadcast PBFT-style after the slow-path timer.
    Prepare,
    Commit,
}

/// A sign-share, prepare, or commit vote for (view, seq, content digest).
#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub phase: Phase,
    pub view: View,
    pub seq: Seq,
    pub digest: Digest,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        phase: Phase,
        view: View,
        seq: Seq,
        digest: Digest,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            phase,
            view,
            seq,
            digest,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> SbftResult<()> {
        ensure!(
            committee.exists(&self.author),
            SbftError::UnknownAuthority(self.author)
        );
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(SbftError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(match self.phase {
            Phase::SignShare => [2u8],
            Phase::Prepare => [0u8],
            Phase::Commit => [1u8],
        });
        hasher.update(self.view.to_le_bytes());
        hasher.update(self.seq.to_le_bytes());
        hasher.update(&self.digest);
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{:?}(v{}, n{}, {}, author {})",
            self.phase, self.view, self.seq, self.digest, self.author
        )
    }
}

/// Proof that (view, seq, content digest) prepared on the slow path: the
/// original pre-prepare plus a quorum of prepare votes. Carried inside
/// view-change messages so prepared content survives into the next view.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PreparedCert {
    pub batch: Batch,
    pub prepares: Vec<Vote>,
}

impl PreparedCert {
    pub fn verify(&self, committee: &Committee) -> SbftResult<()> {
        self.batch.verify(committee)?;
        let digest = self.batch.content_digest();
        let mut authors = std::collections::HashSet::new();
        for vote in &self.prepares {
            ensure!(
                vote.phase == Phase::Prepare
                    && vote.view == self.batch.view
                    && vote.seq == self.batch.seq
                    && vote.digest == digest,
                SbftError::MalformedCertificate(self.batch.seq)
            );
            ensure!(
                authors.insert(vote.author),
                SbftError::MalformedCertificate(self.batch.seq)
            );
            vote.verify(committee)?;
        }
        ensure!(
            authors.len() >= committee.quorum_threshold(),
            SbftError::MalformedCertificate(self.batch.seq)
        );
        Ok(())
    }
}

/// One replica's own sign-share plus the batch it signed, carried inside its
/// view-change message. A value that fast-committed carries a share from
/// every correct replica, so it shows up at least f+1 times in any
/// view-change quorum and the new leader must re-propose it.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShareEvidence {
    pub batch: Batch,
    pub share: Vote,
}

impl ShareEvidence {
    pub fn verify(&self, committee: &Committee, owner: &PublicKey) -> SbftResult<()> {
        self.batch.verify(committee)?;
        ensure!(
            self.share.phase == Phase::SignShare
                && self.share.author == *owner
                && self.share.view == self.batch.view
                && self.share.seq == self.batch.seq
                && self.share.digest == self.batch.content_digest(),
            SbftError::MalformedCertificate(self.batch.seq)
        );
        self.share.verify(committee)
    }
}

/// Proof that (seq, content digest) committed, either on the fast path (a
/// sign-share from every replica, aggregated by the collector) or on the
/// slow path (a quorum of commit votes). Broadcast by the collector for fast
/// commits and used for laggard catch-up sync on both paths; carries the
/// payload needed to deliver.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitCert {
    pub seq: Seq,
    pub payload: Vec<Digest>,
    pub commits: Vec<Vote>,
}

impl CommitCert {
    pub fn is_fast(&self) -> bool {
        self.commits
            .first()
            .map(|v| v.phase == Phase::SignShare)
            .unwrap_or(false)
    }

    pub fn verify(&self, committee: &Committee) -> SbftResult<()> {
        let digest = content_digest(&self.payload);
        let (view, phase) = match self.commits.first() {
            Some(v) => (v.view, v.phase),
            None => return Err(SbftError::MalformedCertificate(self.seq)),
        };
        ensure!(
            phase == Phase::SignShare || phase == Phase::Commit,
            SbftError::MalformedCertificate(self.seq)
        );
        let mut authors = std::collections::HashSet::new();
        for vote in &self.commits {
            ensure!(
                vote.phase == phase
                    && vote.view == view
                    && vote.seq == self.seq
                    && vote.digest == digest,
                SbftError::MalformedCertificate(self.seq)
            );
            ensure!(
                authors.insert(vote.author),
                SbftError::MalformedCertificate(self.seq)
            );
            vote.verify(committee)?;
        }
        let required = match phase {
            Phase::SignShare => committee.fast_threshold(),
            _ => committee.quorum_threshold(),
        };
        ensure!(
            authors.len() >= required,
            SbftError::MalformedCertificate(self.seq)
        );
        Ok(())
    }
}

/// Vote to move to `view`, carrying everything prepared beyond what this
/// replica has delivered plus its own sign-shares (fast-path evidence).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ViewChangeMsg {
    pub view: View,
    pub last_delivered: Seq,
    pub prepared: Vec<PreparedCert>,
    pub shares: Vec<ShareEvidence>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl ViewChangeMsg {
    pub async fn new(
        view: View,
        last_delivered: Seq,
        prepared: Vec<PreparedCert>,
        shares: Vec<ShareEvidence>,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let msg = Self {
            view,
            last_delivered,
            prepared,
            shares,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(msg.digest()).await;
        Self { signature, ..msg }
    }

    pub fn verify(&self, committee: &Committee) -> SbftResult<()> {
        ensure!(
            committee.exists(&self.author),
            SbftError::UnknownAuthority(self.author)
        );
        self.signature.verify(&self.digest(), &self.author)?;
        for cert in &self.prepared {
            ensure!(
                cert.batch.seq > self.last_delivered,
                SbftError::MalformedCertificate(cert.batch.seq)
            );
            cert.verify(committee)?;
        }
        for evidence in &self.shares {
            ensure!(
                evidence.batch.seq > self.last_delivered,
                SbftError::MalformedCertificate(evidence.batch.seq)
            );
            evidence.verify(committee, &self.author)?;
        }
        Ok(())
    }
}

impl Hash for ViewChangeMsg {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.view.to_le_bytes());
        hasher.update(self.last_delivered.to_le_bytes());
        for cert in &self.prepared {
            hasher.update(Hash::digest(&cert.batch));
            hasher.update((cert.prepares.len() as u64).to_le_bytes());
        }
        for evidence in &self.shares {
            hasher.update(Hash::digest(&evidence.batch));
            hasher.update(Hash::digest(&evidence.share));
        }
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

/// The new leader's proof for entering `view`: a quorum of view-change
/// messages plus the pre-prepares (signed in the new view) that re-propose
/// all content that may have committed and fill gaps with empty batches.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewViewMsg {
    pub view: View,
    pub view_changes: Vec<ViewChangeMsg>,
    pub pre_prepares: Vec<Batch>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl NewViewMsg {
    pub async fn new(
        view: View,
        view_changes: Vec<ViewChangeMsg>,
        pre_prepares: Vec<Batch>,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let msg = Self {
            view,
            view_changes,
            pre_prepares,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(msg.digest()).await;
        Self { signature, ..msg }
    }

    /// Signature and certificate checks only; the selection logic (that the
    /// pre-prepares faithfully re-propose the right content) is validated by
    /// the state machine.
    pub fn verify(&self, committee: &Committee) -> SbftResult<()> {
        ensure!(
            self.author == committee.leader(self.view),
            SbftError::WrongLeader {
                view: self.view,
                author: self.author
            }
        );
        self.signature.verify(&self.digest(), &self.author)?;
        let mut authors = std::collections::HashSet::new();
        for vc in &self.view_changes {
            ensure!(
                vc.view == self.view,
                SbftError::MalformedNewView(self.view)
            );
            ensure!(
                authors.insert(vc.author),
                SbftError::MalformedNewView(self.view)
            );
            vc.verify(committee)?;
        }
        ensure!(
            authors.len() >= committee.quorum_threshold(),
            SbftError::MalformedNewView(self.view)
        );
        for batch in &self.pre_prepares {
            ensure!(
                batch.view == self.view && batch.author == self.author,
                SbftError::MalformedNewView(self.view)
            );
            batch.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for NewViewMsg {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.view.to_le_bytes());
        for vc in &self.view_changes {
            hasher.update(Hash::digest(vc));
        }
        for batch in &self.pre_prepares {
            hasher.update(Hash::digest(batch));
        }
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

/// Wire messages between replicas.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SbftMessage {
    PrePrepare(Batch),
    /// Sign-shares travel point-to-point to the collector; prepare and
    /// commit votes are broadcast. Both use this variant.
    Vote(Vote),
    /// The collector's aggregated fast-path (or a synced slow-path) commit
    /// proof.
    FastCommit(CommitCert),
    ViewChange(ViewChangeMsg),
    NewView(NewViewMsg),
    /// Laggard catch-up: ask for commit certificates in a range.
    SyncRequest {
        from: Seq,
        to: Seq,
        requester: PublicKey,
    },
    SyncReply(Vec<CommitCert>),
}
