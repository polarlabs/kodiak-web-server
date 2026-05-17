use crate::util::json_schema;

enum CreateTable {
    Sqlite(super::sqlite::CreateTable),
}

enum ColumnDefinitions {
    Sqlite(super::sqlite::ColumnDefinitions),
}

enum Type {
    Sqlite(super::sqlite::Type),
}

impl TryFrom<json_schema::Definition> for CreateTable {
    type Error = ();

    fn try_from(value: json_schema::Definition) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl TryFrom<json_schema::Property> for ColumnDefinitions {
    type Error = ();

    fn try_from(value: json_schema::Property) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl TryFrom<json_schema::Type> for Type {
    type Error = ();

    fn try_from(value: json_schema::Type) -> Result<Self, Self::Error> {
        todo!()
    }
}
