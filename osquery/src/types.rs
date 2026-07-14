use std::collections::HashMap;

/// A single result row: osquery's own row representation is fundamentally
/// a map of column name to string value (see `osquery::Row` /
/// `osquery::QueryData` upstream), so no richer typing is lost here.
pub type Row = HashMap<String, String>;

/// The shim returns a bare JSON array of row objects (see
/// `osquery::serializeQueryDataJSON`), so this wrapper deserializes
/// transparently from that array -- there is no wrapping `{"rows": [...]}`
/// envelope on the wire.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct QueryResult<T = Row> {
    pub rows: Vec<T>,
}
