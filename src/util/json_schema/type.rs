#[derive(Clone)]
pub(in crate::util) enum Type {
    Boolean,
    Decimal,
    Integer,
    Null,
    Text,
    Unsupported,
}

impl From<&json_schema::Type> for Type {
    fn from(value: &json_schema::Type) -> Self {
        match value {
            json_schema::Type::SimpleTypes(r#type) => match r#type {
                json_schema::SimpleTypes::Array => Type::Unsupported,
                json_schema::SimpleTypes::Boolean => Type::Boolean,
                json_schema::SimpleTypes::Integer => Type::Integer,
                json_schema::SimpleTypes::Null => Type::Null,
                json_schema::SimpleTypes::Number => Type::Decimal,
                json_schema::SimpleTypes::Object => Type::Unsupported,
                json_schema::SimpleTypes::String => Type::Text,
            },
            json_schema::Type::ArrayOfSimpleTypes(r#type) => match r#type {
                _ => Type::Unsupported,
            },
        }
    }
}
