use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(Utc::now())
    }

    // Ensure consistent format of timestamps.
    // "2018-01-26T18:30:09.453735Z"
    pub fn to_string(&self) -> String {
        self.0.to_rfc3339_opts(SecondsFormat::Micros, true)
    }
}

impl TryFrom<String> for Timestamp {
    type Error = chrono::format::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let d = DateTime::parse_from_rfc3339(&value)?;
        let d = d.with_timezone(&Utc);
        Ok(Timestamp(d))
    }
}

impl TryFrom<crate::db::Timestamp> for Timestamp {
    type Error = chrono::format::ParseError;

    fn try_from(value: crate::db::Timestamp) -> Result<Self, Self::Error> {
        let ts = Timestamp::try_from(value.0)?;
        Ok(ts)
    }
}

impl TryFrom<crate::db::TimestampOption> for Timestamp {
    type Error = chrono::format::ParseError;

    fn try_from(value: crate::db::TimestampOption) -> Result<Self, Self::Error> {
        match value.0 {
            None => Ok(Timestamp(DateTime::UNIX_EPOCH)),
            Some(value) => {
                let ts = Timestamp::try_from(value)?;
                Ok(ts)
            }
        }
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tscreated_from_string() {
        let datetime = String::from("2024-10-19T15:37:14.116153504+00:00");

        let d = Timestamp::from(datetime);

        assert!(d.0.is_some());
    }
}
*/
