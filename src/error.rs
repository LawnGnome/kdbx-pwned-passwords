use std::path::PathBuf;

use indicatif::style::TemplateError;
use kdbx_rs::errors::{OpenError, UnlockError};
use reqwest::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot build reqwest client: {0}")]
    ClientBuild(reqwest::Error),

    #[error("cannot read keyfile {path:?}: {e}")]
    Keyfile {
        #[source]
        e: std::io::Error,
        path: PathBuf,
    },

    #[error(transparent)]
    KdbxFailedUnlock(#[from] UnlockError),

    #[error(transparent)]
    KdbxOpen(#[from] OpenError),

    #[error("cannot read password: {0}")]
    PasswordRead(#[source] std::io::Error),

    #[error("sending request: {0}")]
    RequestSend(#[source] reqwest::Error),

    #[error("response malformed")]
    ResponseMalformed,

    #[error("reading response: {0}")]
    ResponseRead(#[source] std::io::Error),

    #[error("unexpected response status: {0}")]
    ResponseStatus(StatusCode),

    #[error("retry-after header is not a number")]
    RetryAfterMalformed,

    #[error("no retry-after header in 429 response")]
    RetryAfterMissing,

    #[error(transparent)]
    Template(#[from] TemplateError),
}
