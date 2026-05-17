use crate::util::Timestamp;
use crate::util::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub struct Schema {
    uuid: Uuid,
    name: String,
    ts_created: Timestamp,
    ts_updated: Option<Timestamp>,
}

impl Schema {
    pub fn new(name: &str) -> Self {
        Schema {
            uuid: Uuid::new(),
            name: name.to_string(),
            ts_created: Timestamp::now(),
            ts_updated: None,
        }
    }

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn ts_created(&self) -> &Timestamp {
        &self.ts_created
    }
}

impl TryFrom<crate::db::Schema> for Schema {
    type Error = chrono::format::ParseError;

    fn try_from(value: crate::db::Schema) -> Result<Self, Self::Error> {
        let ts_created = Timestamp::try_from(value.ts_created)?;
        let ts_updated = Timestamp::try_from(value.ts_updated)?;

        Ok(Schema {
            uuid: Uuid::parse_str(&value.uuid.0).unwrap(),
            name: value.name,
            ts_created,
            ts_updated: Some(ts_updated),
        })
    }
}

impl TryInto<crate::db::Schema> for Schema {
    type Error = ();

    fn try_into(self) -> Result<crate::db::Schema, Self::Error> {
        let ts_updated = match self.ts_updated {
            None => crate::db::TimestampOption(None),
            Some(ts) => crate::db::TimestampOption(Some(ts.to_string())),
        };

        Ok(crate::db::Schema {
            id: crate::db::schema::SchemaPK(0),
            uuid: crate::db::schema::SchemaUuid(String::from(self.uuid)),
            name: self.name,
            ts_created: crate::db::Timestamp(self.ts_created.to_string()),
            ts_updated,
        })
    }
}

impl From<crate::webapi::SchemaCreateReq> for Schema {
    fn from(value: crate::webapi::SchemaCreateReq) -> Self {
        Schema {
            uuid: Uuid::new(),
            name: value.name().to_string(),
            ts_created: Timestamp::now(),
            ts_updated: None,
        }
    }
}
