use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexCodecError {
    InvalidHexCharacter,
    InvalidHexLength,
}

impl fmt::Display for HexCodecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidHexCharacter => write!(f, "Invalid hex character"),
            Self::InvalidHexLength => write!(f, "Invalid hex string length"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECError {
    InvalidPublicKey,
}

impl fmt::Display for ECError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    BadMac,
    InvalidBlockSize,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::BadMac => write!(f, "Invalid Mac"),
            Self::InvalidBlockSize => write!(f, "Invalid Block Size"),
        }
    }
}
