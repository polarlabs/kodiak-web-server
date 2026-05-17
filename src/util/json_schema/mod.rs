mod definition;
pub(in super::super::util) use definition::Definition;
pub(in super::super::util) use definition::Definitions;

mod property;
pub(in super::super::util) use property::Properties;
pub(in super::super::util) use property::Property;

mod r#type;
pub(in super::super::util) use r#type::Type;

mod schema;
pub(in super::super::util) use schema::Schema;

use json_schema::{JSONSchema, JSONSchemaObject, SimpleTypes, StringArray};

use std::str::FromStr;

///
/// {
///   "$schema": "https://json-schema.org/draft/2020-12/schema"
/// }
///

pub(crate) fn json_schema_example_0() -> Schema {
    let json_schema = r#"{
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "definitions": {
            "vehicle": {
                "type": "object",
                "properties": {
                    "brand": {
                        "type": "string",
                        "enum": ["ford","toyota"]
                    },
                    "dateOfManufacture": {
                        "type": "string",
                        "format": "datetime"
                    },
                    "nr_doors": {
                        "type": "integer"
                    },
                    "hubraum": {
                        "type": "number"
                    }
                }
            }
        }
    }"#;

    let json_schema = Schema::from_str(json_schema).unwrap();
    json_schema
}

pub(crate) fn json_schema_example_00() -> Definitions {
    let json_schema = json_schema_example_0();
    json_schema.definitions()
}

fn json_schema_example_1() -> JSONSchemaObject {
    let json_schema = r#"{
    "properties": {
                "brand": {
                    "type": "string",
                    "enum": ["ford","toyota"]
                },
                "dateOfManufacture": {
                    "type": "string",
                    "format": "datetime"
                },
                "nr_doors": {
                    "type": "integer"
                },
                "hubraum": {
                    "type": "number"
                }
            }
    }"#;

    let json_schema: JSONSchemaObject = serde_json::from_str(json_schema).unwrap();
    json_schema
}

// Transfer JSON Schema into CREATE TABLE statement
// Example:
/*
Mapping
JSON Schema to          Kodiak            sqlite
String                  String            TEXT
Number                  Decimal           REAL
Integer                 Integer           INTEGER
Boolean                 Bool              ?
Null                    n/a               NULL
Object                  another concept   another table
Array with item type    Vec<item type>    ?
Array w/o item type     n/a               n/a

https://json-schema.org/understanding-json-schema/reference/array

The additionalProperties keyword is used to control the handling of extra stuff, that is, properties whose names are not listed in the properties keyword or match any of the regular expressions in the patternProperties keyword. By default any additional properties are allowed.
"additionalProperties": false
"unevaluatedProperties": false

{
      "type": "object",
      "properties": {
        "street_address": { "type": "string" },
        "city": { "type": "string" },
        "state": { "type": "string" }
      },
      "required": ["street_address", "city", "state"],
      "additionalProperties": false
    }

{
    "$schema": "http://json-schema.org/draft-07/schema",
    "definitions": {
        "vehicle": {
            "type": "object",
            "properties": {
                "brand": {
                    "type": "string",
                    "enum": ["ford","toyota"]
                },
                "dateOfManufacture": {
                    "type": "string"
                }
            }
        }
    },
    "type": "object",
    "properties": {
        "primary": { "$ref": "#/definitions/vehicle" },
        "secondary": { "$ref": "#/definitions/vehicle" }
    }
}
employee {
    name: String,
    n_kids: Integer,
}

employee {
    name: String,
    n_kids: Integer,
}

CREATE TABLE IF NOT EXISTS employee (id INTEGER NOT NULL PRIMARY KEY, name TEXT, n_kids INTEGER) STRICT;

{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "employee": {
      "type": "object",
      "properties": {
        "name": {
          "type": "string"
        },
        "n_kids": {
          "type": "integer"
        }
      },
      "required": [
        "name",
        "n_kids"
      ]
    }
  },
  "required": [
    "employee"
  ]
}

{
      "$id": "https://example.com/person.schema.json",
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "title": "Hello World!",
      "type": "object",
      "properties": { },
      "description": "My first JSON Schema."
}
*/

pub fn test() {
    let foo = r#"{
        "title": "helloworld",
        "type": "string"
    }"#;

    let foo = r#"{
    "definitions": {
        "vehicle": {
            "type": "object",
            "properties": {
                "brand": {
                    "type": "string",
                    "enum": ["ford","toyota"]
                },
                "dateOfManufacture": {
                    "type": "string",
                    "format": "datetime"
                },
                "nr_doors": {
                    "type": "integer"
                },
                "hubraum": {
                    "type": "number"
                }
            }
        }
    }
    }"#;

    let as_json_schema: JSONSchemaObject = serde_json::from_str(foo).unwrap();

    for defs in as_json_schema.definitions.iter() {
        for (key, value) in defs.iter() {
            println!("Defined object: {}", key);

            match value {
                JSONSchema::JSONSchemaObject(value) => {
                    for props in value.properties.iter() {
                        for (key, value) in props {
                            println!("Defined property: {:?}", key);

                            match value {
                                JSONSchema::JSONSchemaObject(value) => {
                                    if let Some(t) = &value._type {
                                        match t {
                                            json_schema::Type::SimpleTypes(t) => {
                                                println!("Type: {:?}", t);
                                            }
                                            json_schema::Type::ArrayOfSimpleTypes(v) => {}
                                        }
                                    }

                                    if let Some(f) = &value.format {
                                        println!("Format: {:?}", f);
                                    }
                                }
                                JSONSchema::JSONSchemaBoolean(_) => {}
                            }
                        }
                    }
                }
                JSONSchema::JSONSchemaBoolean(_) => {}
            }
        }
    }
}
