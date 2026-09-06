use crate::messages::{Seq, View};
use crypto::{CryptoError, PublicKey};
use store::StoreError;
use thiserror::Error;

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err($e);
        }
    };
}

pub type PbftResult<T> = Result<T, PbftError>;

#[derive(Error, Debug)]
pub enum PbftError {
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] Box<bincode::ErrorKind>),

    #[error("Store error: {0}")]
    StoreError(#[from] StoreError),

    #[error("Invalid signature: {0}")]
    InvalidSignature(#[from] CryptoError),

    #[error("Unknown authority {0}")]
    UnknownAuthority(PublicKey),

    #[error("Malformed certificate for seq {0}")]
    MalformedCertificate(Seq),

    #[error("Malformed new-view for view {0}")]
    MalformedNewView(View),

    #[error("Message from wrong leader {author} for view {view}")]
    WrongLeader { view: View, author: PublicKey },

    #[error("Invalid payload")]
    InvalidPayload,
}
