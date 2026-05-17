use super::super::super::util::json_schema::{Properties, Type};
use json_schema::JSONSchema;

pub(in super::super::super::util) struct Definitions(Vec<Definition>);

#[derive(Clone)]
pub(in super::super::super::util) struct Definition {
    name: String,
    properties: Properties,
}

impl Definitions {
    fn new() -> Self {
        Definitions(Vec::new())
    }

    fn push(&mut self, definition: Definition) {
        self.0.push(definition);
    }

    pub(crate) fn first(&self) -> Option<&Definition> {
        self.0.first()
    }
}

impl Definition {
    fn new(name: &str, properties: Properties) -> Self {
        Definition {
            name: name.to_string(),
            properties,
        }
    }

    pub(in crate::util) fn name(&self) -> String {
        self.name.to_string()
    }

    pub(in crate::util) fn properties(self) -> Properties {
        self.properties
    }

    pub(in crate::util) fn has_properties(&self) -> bool {
        !self.properties.is_empty()
    }
}

impl From<&json_schema::Definitions> for Definitions {
    fn from(value: &json_schema::Definitions) -> Self {
        let mut definitions = Definitions::new();

        for (key, value) in value {
            match value {
                JSONSchema::JSONSchemaObject(object) => {
                    if let Some(properties) = &object.properties {
                        let properties = Properties::from(properties);
                        let definition = Definition::new(key, properties);
                        definitions.push(definition);
                    } else {
                        log::warn!("Definition {} has no properties.", key);
                    }
                }
                JSONSchema::JSONSchemaBoolean(boolean) => {
                    log::debug!("JSONSchemaBoolean {} not supported.", boolean);
                }
            }
        }

        definitions
    }
}
