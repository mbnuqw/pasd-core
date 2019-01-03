use std::error;
use std::io;
use std::fmt;
use block_modes;
use block_cipher_trait;
use scrypt::errors::{InvalidOutputLen, InvalidParams};
use msgpack;
use con;

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    JSON(serde_json::Error),
    MSGPACKENC(msgpack::encode::Error),
    MSGPACKDEC(msgpack::decode::Error),
    CRYPTO(block_modes::BlockModeError),
    SCRYPTLEN(InvalidOutputLen),
    SCRYPTPARAM(InvalidParams),
    KEYLEN(block_cipher_trait::InvalidKeyLength),
    CON(con::Error),
    Other(&'static str),
    Internal,
    NotFound,
    IncorrectConf,
    IncorrectReq,
    IncorrectOuterKey,
    Duplicate,
    InvalidKey,
    NotEnoughKeys,
    Unknown,
}

impl Error {
    pub fn description(&self) -> &str {
        match self {
            Error::IO(_) => "io",
            Error::JSON(_) => "json",
            Error::MSGPACKENC(_) => "msgpack-encoding",
            Error::MSGPACKDEC(_) => "msgpack-decoding",
            Error::CRYPTO(_) => "crypto",
            Error::SCRYPTLEN(_) => "scrypt-len",
            Error::SCRYPTPARAM(_) => "scrypt-param",
            Error::KEYLEN(_) => "key-len",
            Error::CON(_) => "con",
            Error::Other(msg) => msg,
            Error::Internal => "internal",
            Error::NotFound => "not-found",
            Error::IncorrectConf => "incorrect-config",
            Error::IncorrectReq => "incorrect-request",
            Error::IncorrectOuterKey => "incorrect-outer-key",
            Error::Duplicate => "duplicate",
            Error::InvalidKey => "invalid-key",
            Error::NotEnoughKeys => "not-enough-keys",
            _ => "unknown",
        }
    }

    pub fn cause(&self) -> Option<&error::Error> {
        match self {
            Error::IO(err) => Some(err),
            _ => None,
        }
    }

    pub fn json(&self) -> String {
        match self {
            Error::IO(_) => "io".to_string(),
            Error::JSON(_) => "json".to_string(),
            Error::MSGPACKENC(_) => "msgpack-encoding".to_string(),
            Error::MSGPACKDEC(_) => "msgpack-decoding".to_string(),
            Error::CRYPTO(_) => "crypto".to_string(),
            Error::SCRYPTLEN(_) => "scrypt-len".to_string(),
            Error::SCRYPTPARAM(_) => "scrypt-param".to_string(),
            Error::KEYLEN(_) => "key-len".to_string(),
            Error::CON(_) => "con".to_string(),
            Error::Other(msg) => "other-".to_string() + msg,
            Error::Internal => "internal".to_string(),
            Error::NotFound => "not-found".to_string(),
            Error::IncorrectConf => "incorrenct-config".to_string(),
            Error::IncorrectReq => "incorrenct-request".to_string(),
            Error::IncorrectOuterKey => "incorrect-outer-key".to_string(),
            Error::Duplicate => "duplicate".to_string(),
            Error::InvalidKey => "invalid-key".to_string(),
            Error::NotEnoughKeys => "not-enough-keys".to_string(),
            _ => "unknown".to_string(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IO(err) => err.fmt(f),
            Error::JSON(err) => err.fmt(f),
            Error::MSGPACKENC(err) => err.fmt(f),
            Error::MSGPACKDEC(err) => err.fmt(f),
            Error::CRYPTO(_) => write!(f, "Crypto error"),
            Error::SCRYPTLEN(err) => err.fmt(f),
            Error::SCRYPTPARAM(err) => err.fmt(f),
            Error::KEYLEN(err) => err.fmt(f),
            Error::CON(err) => err.fmt(f),
            Error::Other(_) => write!(f, "Some other error"),
            Error::Internal => write!(f, "Internal error"),
            Error::NotFound => write!(f, "Not found"),
            Error::IncorrectConf => write!(f, "Incorrect config"),
            Error::IncorrectReq => write!(f, "Incorrect request"),
            Error::IncorrectOuterKey => write!(f, "Incorrect outer key"),
            Error::Duplicate => write!(f, "Duplicate"),
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::NotEnoughKeys => write!(f, "Not enough keys"),
            _ => write!(f, "Unknown error"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IO(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::JSON(error)
    }
}

impl From<con::Error> for Error {
    fn from(error: con::Error) -> Self {
        Error::CON(error)
    }
}

impl From<msgpack::encode::Error> for Error {
    fn from(error: msgpack::encode::Error) -> Self {
        Error::MSGPACKENC(error)
    }
}

impl From<msgpack::decode::Error> for Error {
    fn from(error: msgpack::decode::Error) -> Self {
        Error::MSGPACKDEC(error)
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(error: block_modes::BlockModeError) -> Self {
        Error::CRYPTO(error)
    }
}

impl From<block_cipher_trait::InvalidKeyLength> for Error {
    fn from(error: block_cipher_trait::InvalidKeyLength) -> Self {
        Error::KEYLEN(error)
    }
}

impl From<InvalidOutputLen> for Error {
    fn from(error: InvalidOutputLen) -> Self {
        Error::SCRYPTLEN(error)
    }
}

impl From<InvalidParams> for Error {
    fn from(error: InvalidParams) -> Self {
        Error::SCRYPTPARAM(error)
    }
}
