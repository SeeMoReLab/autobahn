use crate::config::Committee;
use crate::error::{PbftError, PbftResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;

pub type View = u64;
pub type Seq = u64;

/// Digest binding only the payload content. Prepared certificates bind this
/// digest (with view and seq carried in the votes), so a new leader can
/// re-pre-prepare the same content in a later view and existing certificates
/// still refer to it.
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

    pub fn verify(&self, committee: &Committee) -> PbftResult<()> {
        ensure!(
            committee.exists(&self.author),
            PbftError::UnknownAuthority(self.author)
        );
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(PbftError::from)
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
    Prepare,
    Commit,
}

/// A prepare or commit vote for (view, seq, content digest).
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

    pub fn verify(&self, committee: &Committee) -> PbftResult<()> {
        ensure!(
            committee.exists(&self.author),
            PbftError::UnknownAuthority(self.author)
        );
        self.signature
            .verify(&self.digest(), &self.author)
            .map_err(PbftError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(match self.phase {
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

/// Proof that (view, seq, content digest) prepared: the original pre-prepare
/// plus a quorum of prepare votes. Carried inside view-change messages so
/// prepared content survives into the next view.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PreparedCert {
    pub batch: Batch,
    pub prepares: Vec<Vote>,
}

impl PreparedCert {
    pub fn verify(&self, committee: &Committee) -> PbftResult<()> {
        self.batch.verify(committee)?;
        let digest = self.batch.content_digest();
        let mut authors = std::collections::HashSet::new();
        for vote in &self.prepares {
            ensure!(
                vote.phase == Phase::Prepare
                    && vote.view == self.batch.view
                    && vote.seq == self.batch.seq
                    && vote.digest == digest,
                PbftError::MalformedCertificate(self.batch.seq)
            );
            ensure!(
                authors.insert(vote.author),
                PbftError::MalformedCertificate(self.batch.seq)
            );
            vote.verify(committee)?;
        }
        ensure!(
            authors.len() >= committee.quorum_threshold(),
            PbftError::MalformedCertificate(self.batch.seq)
        );
        Ok(())
    }
}

/// Proof that (seq, content digest) committed: a quorum of commit votes plus
/// the payload needed to deliver it. Used for laggard catch-up sync.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitCert {
    pub seq: Seq,
    pub payload: Vec<Digest>,
    pub commits: Vec<Vote>,
}

impl CommitCert {
    pub fn verify(&self, committee: &Committee) -> PbftResult<()> {
        let digest = content_digest(&self.payload);
        let (view, some_vote) = match self.commits.first() {
            Some(v) => (v.view, v),
            None => return Err(PbftError::MalformedCertificate(self.seq)),
        };
        let _ = some_vote;
        let mut authors = std::collections::HashSet::new();
        for vote in &self.commits {
            ensure!(
                vote.phase == Phase::Commit
                    && vote.view == view
                    && vote.seq == self.seq
                    && vote.digest == digest,
                PbftError::MalformedCertificate(self.seq)
            );
            ensure!(
                authors.insert(vote.author),
                PbftError::MalformedCertificate(self.seq)
            );
            vote.verify(committee)?;
        }
        ensure!(
            authors.len() >= committee.quorum_threshold(),
            PbftError::MalformedCertificate(self.seq)
        );
        Ok(())
    }
}

/// Vote to move to `view`, carrying everything prepared beyond what this
/// replica has delivered.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ViewChangeMsg {
    pub view: View,
    pub last_delivered: Seq,
    pub prepared: Vec<PreparedCert>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl ViewChangeMsg {
    pub async fn new(
        view: View,
        last_delivered: Seq,
        prepared: Vec<PreparedCert>,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let msg = Self {
            view,
            last_delivered,
            prepared,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(msg.digest()).await;
        Self { signature, ..msg }
    }

    pub fn verify(&self, committee: &Committee) -> PbftResult<()> {
        ensure!(
            committee.exists(&self.author),
            PbftError::UnknownAuthority(self.author)
        );
        self.signature.verify(&self.digest(), &self.author)?;
        for cert in &self.prepared {
            ensure!(
                cert.batch.seq > self.last_delivered,
                PbftError::MalformedCertificate(cert.batch.seq)
            );
            cert.verify(committee)?;
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
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

/// The new leader's proof for entering `view`: a quorum of view-change
/// messages plus the pre-prepares (signed in the new view) that re-propose
/// all prepared content and fill gaps with empty batches.
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
    /// pre-prepares faithfully re-propose the highest prepared content) is
    /// validated by the state machine.
    pub fn verify(&self, committee: &Committee) -> PbftResult<()> {
        ensure!(
            self.author == committee.leader(self.view),
            PbftError::WrongLeader {
                view: self.view,
                author: self.author
            }
        );
        self.signature.verify(&self.digest(), &self.author)?;
        let mut authors = std::collections::HashSet::new();
        for vc in &self.view_changes {
            ensure!(
                vc.view == self.view,
                PbftError::MalformedNewView(self.view)
            );
            ensure!(
                authors.insert(vc.author),
                PbftError::MalformedNewView(self.view)
            );
            vc.verify(committee)?;
        }
        ensure!(
            authors.len() >= committee.quorum_threshold(),
            PbftError::MalformedNewView(self.view)
        );
        for batch in &self.pre_prepares {
            ensure!(
                batch.view == self.view && batch.author == self.author,
                PbftError::MalformedNewView(self.view)
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
pub enum PbftMessage {
    PrePrepare(Batch),
    Vote(Vote),
    ViewChange(ViewChangeMsg),
    NewView(NewViewMsg),
    /// Laggard catch-up: ask `author` for commit certificates in a range.
    SyncRequest {
        from: Seq,
        to: Seq,
        requester: PublicKey,
    },
    SyncReply(Vec<CommitCert>),
}
