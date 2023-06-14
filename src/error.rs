use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexCodecError {
    InvalidHexCharacter,
    InvalidHexLength,
}

impl fmt::Display for HexCodecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidHexCharacter => f.write_str("Invalid hex character"),
            Self::InvalidHexLength => f.write_str("Invalid hex string length"),
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
            Self::InvalidPublicKey => f.write_str("Invalid public key"),
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
            Self::BadMac => f.write_str("Invalid Mac"),
            Self::InvalidBlockSize => f.write_str("Invalid Block Size"),
        }
    }
}
