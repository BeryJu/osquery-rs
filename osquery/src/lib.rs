//! Safe API for an in-process embedded osquery runtime: no `osqueryd`
//! subprocess, no Thrift extensions socket on disk. See
//! [`OsqueryInstance`] for the entry point and its documented caveats
//! (process-wide singleton, global signal handlers).

mod error;
mod instance;
mod logging;
mod types;

pub use error::OsqueryError;
pub use instance::OsqueryInstance;
pub use types::{QueryResult, Row};
