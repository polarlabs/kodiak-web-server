use super::Type;
use json_schema::JSONSchema;

#[derive(Clone)]
pub(in crate::util) struct Properties(Vec<Property>);

impl Properties {
    pub(super) fn new() -> Self {
        Properties(Vec::new())
    }

    fn push(&mut self, property: Property) {
        self.0.push(property);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone)]
pub(in crate::util) struct Property {
    name: String,
    t: Type,
    required: bool,
}

impl Property {
    fn new(name: &str, t: Type, required: bool) -> Self {
        Property {
            name: name.to_string(),
            t,
            required,
        }
    }

    pub(in crate::util) fn name(&self) -> String {
        self.name.to_string()
    }

    pub(in crate::util) fn t(&self) -> Type {
        self.t.clone()
    }

    pub(in crate::util) fn required(&self) -> bool {
        self.required
    }
}

impl From<&json_schema::Properties> for Properties {
    fn from(value: &json_schema::Properties) -> Self {
        let mut properties = Properties::new();

        for (key, value) in value {
            match value {
                JSONSchema::JSONSchemaObject(object) => {
                    if let Some(r#type) = &object._type {
                        let property = Property::new(key, Type::from(r#type), false);
                        properties.push(property);
                    } else {
                        log::debug!("JSONSchemaObject {:?} has no type.", object);
                    }
                }
                JSONSchema::JSONSchemaBoolean(boolean) => {
                    log::debug!("JSONSchemaBoolean {} not supported.", boolean);
                }
            }
        }

        properties
    }
}

impl IntoIterator for Properties {
    type Item = Property;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
