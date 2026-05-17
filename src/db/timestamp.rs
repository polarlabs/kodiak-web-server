///
/// Timestamp to reflect a record's creation.
///
#[derive(sqlx::Type, Debug)]
#[sqlx(transparent)]
pub struct Timestamp(pub String);

impl From<String> for Timestamp {
    fn from(value: String) -> Self {
        Timestamp(value)
    }
}
