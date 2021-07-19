use http_types::StatusCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("access denied")]
    AccessDenied,
    #[error("HTTP error: {0}")]
    Http(http_types::Error),
    #[error("other error: {0}")]
    Other(String),
}

impl From<http_types::Error> for DaemonError {
    fn from(e: http_types::Error) -> Self {
        if e.status() == StatusCode::Forbidden {
            Self::AccessDenied
        } else {
            Self::Http(e)
        }
    }
}
