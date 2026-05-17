use crate::util::json_schema;
use std::fmt::{Display, Formatter};

// https://www.sqlite.org/lang_createtable.html
pub(in crate::util::sql) struct CreateTable {
    name: String,
    column_definitions: ColumnDefinitions,
    if_not_exists: bool,
    strict: bool,
}

pub(in crate::util::sql) struct ColumnDefinitions(Vec<ColumnDefinition>);

pub(in crate::util::sql) struct ColumnDefinition {
    name: String,
    r#type: Type,
}

pub(in crate::util::sql) enum Type {
    Blob,
    Integer,
    Null,
    Real,
    Text,
}

impl ColumnDefinitions {
    fn new() -> Self {
        ColumnDefinitions(Vec::new())
    }

    fn push(&mut self, column_definition: ColumnDefinition) {
        self.0.push(column_definition);
    }
}

impl TryFrom<json_schema::Definition> for CreateTable {
    type Error = ();

    fn try_from(value: json_schema::Definition) -> Result<Self, Self::Error> {
        if value.has_properties() {
            let mut column_definitions = ColumnDefinitions::new();
            let name = value.name();

            for property in value.properties() {
                match ColumnDefinition::try_from(property) {
                    Ok(column_definition) => column_definitions.push(column_definition),
                    Err(_) => return Err(()),
                }
            }

            let create_table = CreateTable {
                name,
                column_definitions,
                if_not_exists: true,
                strict: true,
            };

            Ok(create_table)
        } else {
            Err(())
        }
    }
}

impl TryFrom<json_schema::Property> for ColumnDefinition {
    type Error = ();

    fn try_from(value: json_schema::Property) -> Result<Self, Self::Error> {
        match Type::try_from(value.t()) {
            Ok(t) => Ok(ColumnDefinition {
                name: value.name(),
                r#type: t,
            }),
            Err(_) => Err(()),
        }
    }
}

impl TryFrom<json_schema::Type> for Type {
    type Error = ();

    fn try_from(value: json_schema::Type) -> Result<Self, Self::Error> {
        match value {
            json_schema::Type::Boolean => Ok(Type::Integer),
            json_schema::Type::Decimal => Ok(Type::Real),
            json_schema::Type::Integer => Ok(Type::Integer),
            json_schema::Type::Null => Ok(Type::Null),
            json_schema::Type::Text => Ok(Type::Text),
            json_schema::Type::Unsupported => Err(()),
        }
    }
}

impl Display for CreateTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut create_table_stmt = "CREATE TABLE".to_string();

        if self.if_not_exists {
            create_table_stmt.push_str(" ");
            create_table_stmt.push_str("IF NOT EXISTS")
        }

        create_table_stmt.push_str(" ");
        create_table_stmt.push_str(self.name.as_str());

        create_table_stmt.push_str(" ");
        create_table_stmt.push_str(self.column_definitions.to_string().as_str());

        if self.strict {
            create_table_stmt.push_str(" ");
            create_table_stmt.push_str("STRICT")
        }

        create_table_stmt.push_str(";");

        write!(f, "{}", create_table_stmt)
    }
}

impl Display for ColumnDefinitions {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut column_definitions = "( ".to_string();
        for (index, column_definition) in self.0.iter().enumerate() {
            column_definitions.push_str(column_definition.to_string().as_str());

            if index + 1 < self.0.len() {
                column_definitions.push_str(", ");
            }
        }
        column_definitions.push_str(" )");

        write!(f, "{}", column_definitions)
    }
}

impl Display for ColumnDefinition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut column_definition = "".to_string();
        column_definition.push_str(self.name.as_str());
        column_definition.push_str(" ");
        column_definition.push_str(self.r#type.to_string().as_str());

        write!(f, "{}", column_definition)
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Type::Blob => String::from("BLOB"),
            Type::Integer => String::from("INTEGER"),
            Type::Null => String::from("NULL"),
            Type::Real => String::from("REAL"),
            Type::Text => String::from("TEXT"),
        };

        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_table_stmt() {
        let json_schema = crate::util::json_schema::json_schema_example_00();
        let definition = json_schema.first().unwrap();
        let create_table_statement = super::CreateTable::try_from(definition.clone()).unwrap();

        println!("Table (TEST): {}", create_table_statement);
    }
}
