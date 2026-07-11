use thiserror::Error;

#[derive(Debug, Error)]
pub enum OsqueryError {
    #[error("osquery embed runtime was already started once in this process")]
    AlreadyInitialized,

    #[error("osquery embed runtime has not been started")]
    NotInitialized,

    #[error("query failed: {message}")]
    QueryFailed { message: String },

    #[error("unexpected error crossing the osquery FFI boundary (code {code})")]
    Ffi { code: i32 },

    #[error("failed to parse query result JSON: {0}")]
    Json(#[from] serde_json::Error),
}
