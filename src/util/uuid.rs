use serde::{Deserialize, Serialize};
use uuid::{Error, Uuid as _U};

// Reserved `Uuid` prefix just in case.
// This is Kodiak in hex.
const KODIAK_RESERVED_UUID_PREFIX: &str = "4b6f6469-616b";

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub(crate) struct Uuid(uuid::Uuid);

impl Uuid {
    // Create a new Uuid ensuring it does not match reserved prefix.
    pub(crate) fn new() -> Uuid {
        loop {
            let uuid = _U::new_v4();
            if !is_reserved(&uuid) {
                return Uuid(uuid);
            }
        }
    }

    pub(crate) fn parse_str(uuid: &String) -> Result<Uuid, Error> {
        match _U::parse_str(uuid) {
            Ok(uuid) => Ok(Uuid(uuid)),
            Err(e) => Err(e),
        }
    }
}

// Check if `Uuid` matches reserved prefix.
fn is_reserved(uuid: &_U) -> bool {
    let mut buffer = _U::encode_buffer();
    let prefix = uuid.as_hyphenated().encode_lower(&mut buffer);

    prefix[0..=12].eq(KODIAK_RESERVED_UUID_PREFIX)
}

impl From<Uuid> for String {
    fn from(value: Uuid) -> Self {
        value.0.as_hyphenated().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_is_reserved_false() {
        let uuid = _U::from_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        assert_eq!(is_reserved(&uuid), false);
    }

    #[test]
    fn test_is_reserved_true() {
        let uuid = _U::from_str(&format!(
            "{}-426f-9247-bb680e5fe0c8",
            KODIAK_RESERVED_UUID_PREFIX
        ))
        .unwrap();
        assert_eq!(is_reserved(&uuid), true);
    }

    #[test]
    fn test_hyphenated_to_hyphenated_string() {
        let uuid = _U::from_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        let uuid = Uuid(uuid);
        assert_eq!(
            String::from(uuid).as_str(),
            "67e55044-10b1-426f-9247-bb680e5fe0c8"
        );
    }

    #[test]
    fn test_non_hyphenated_to_hyphenated_string() {
        let uuid = _U::from_str("67e5504410b1426f9247bb680e5fe0c8").unwrap();
        let uuid = Uuid(uuid);
        assert_eq!(
            String::from(uuid).as_str(),
            "67e55044-10b1-426f-9247-bb680e5fe0c8"
        );
    }
}
