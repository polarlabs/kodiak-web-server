use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(in crate::config) enum Database {
    Internal(InternalDatabase),
    External(ExternalDatabase),
}

#[derive(Clone, Debug, Deserialize)]
struct InternalDatabase {
    url: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ExternalDatabase {
    url: String,
    user: String,
    password: String,
}
