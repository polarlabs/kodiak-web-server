use crate::util::json_schema::Definitions;
use std::str::FromStr;

pub(in crate::util) struct Schema {
    definitions: Definitions,
}

impl Schema {
    fn new(definitions: Definitions) -> Self {
        Schema { definitions }
    }

    pub(in crate::util) fn definitions(self) -> Definitions {
        self.definitions
    }

    // For the time being, Kodiak only supports JSONSchema Dialect 2020-12
    fn is_supported(schema: &json_schema::Schema) -> bool {
        schema
            .as_str()
            .eq("https://json-schema.org/draft/2020-12/schema")
    }
}

enum SupportedJSONSchemas {
    Dialect202012,
}

impl Schema {}

impl FromStr for Schema {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(schema_object) = serde_json::from_str::<json_schema::JSONSchemaObject>(s) {
            if validate(&schema_object) {
                let definitions =
                    Definitions::try_from(&schema_object.definitions.unwrap()).unwrap();

                Ok(Schema::new(definitions))
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }
}

fn validate(json_object: &json_schema::JSONSchemaObject) -> bool {
    let mut valid = true;

    // Schema must use a supported dialect
    if let Some(schema) = &json_object.schema {
        valid = Schema::is_supported(schema);
    } else {
        valid = false
    }

    // Schema must have definitions
    if let Some(_) = json_object.definitions {
        valid = true
    } else {
        valid = false
    }

    valid
}
