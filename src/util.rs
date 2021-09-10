#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    InvalidLength,
    InvalidPadding,
    DecryptionFailure,
    EncryptionFailure,
}

pub type Result<T> = std::result::Result<T, Error>;
