///
/// Timestamp to reflect a record's most recent update.
///
#[derive(sqlx::Type, Debug)]
#[sqlx(transparent)]
pub struct TimestampOption(pub Option<String>);

impl From<Option<String>> for TimestampOption {
    fn from(value: Option<String>) -> Self {
        TimestampOption(value)
    }
}
