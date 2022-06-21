use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexCodecError {
    InvalidHexCharacter,
    InvalidHexLength,
}

impl fmt::Display for HexCodecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HexCodecError::InvalidHexCharacter => write!(f, "Invalid hex character"),
            HexCodecError::InvalidHexLength => write!(f, "Invalid hex string length"),
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
            ECError::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}
