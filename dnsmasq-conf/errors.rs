use std::fmt::Display;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Error {
    IOError(String),
    ParseError(String),
    HeuristicError(String),
    ConfigError(String),
}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            self.variant(),
            match self {
                Self::IOError(e) => e.to_string(),
                Self::ParseError(e) => e.to_string(),
                Self::HeuristicError(e) => e.to_string(),
                Self::ConfigError(e) => e.to_string(),
            }
        )
    }
}
impl Error {
    pub fn variant(&self) -> String {
        match self {
            Error::IOError(_) => "IOError",
            Self::ParseError(_) => "ParseError",
            Self::HeuristicError(_) => "HeuristicError",
            Self::ConfigError(_) => "ConfigError",
        }
        .to_string()
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(format!("{}", e))
    }
}
impl From<iocore::Error> for Error {
    fn from(e: iocore::Error) -> Self {
        Error::IOError(format!("{}", e))
    }
}
impl<R> From<pest::error::Error<R>> for Error
where
    R: pest::RuleType,
{
    fn from(e: pest::error::Error<R>) -> Self {
        Error::ParseError(format!("{}", e))
    }
}
impl From<hickory_proto::ProtoError> for Error {
    fn from(e: hickory_proto::ProtoError) -> Self {
        Error::ParseError(format!("{}", e))
    }
}
impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Error::ParseError(format!("{}", e))
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseError(format!("{}", e))
    }
}
pub type Result<T> = std::result::Result<T, Error>;
