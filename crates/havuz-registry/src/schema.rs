//! JSON Schema generation for connection forms.
//!
//! The admin UI fetches `GET /api/v1/families` and builds its "Add Database"
//! form from the schema returned here. Field order is preserved via
//! `x-havuz-order` because JSON objects carry no ordering guarantee.

use serde_json::{json, Map, Value};

use crate::{ConfigField, FamilyDescriptor, FieldKind};

pub(crate) fn build(family: &FamilyDescriptor) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut order = Vec::new();

    for field in family.config_fields {
        properties.insert(field.name.to_string(), field_schema(field));
        order.push(Value::String(field.name.to_string()));
        // A required field with a default is satisfiable without user input, so
        // it must not appear in the schema's `required` list.
        if field.required && field.default.is_none() {
            required.push(Value::String(field.name.to_string()));
        }
    }

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": format!("havuz:family/{}", family.id),
        "title": family.label,
        "description": family.description,
        "type": "object",
        "additionalProperties": false,
        "properties": Value::Object(properties),
        "required": Value::Array(required),
        "x-havuz-order": Value::Array(order),
    })
}

fn field_schema(field: &ConfigField) -> Value {
    let mut schema = Map::new();
    schema.insert("title".into(), json!(field.label));

    match field.kind {
        FieldKind::Text => {
            schema.insert("type".into(), json!("string"));
        }
        FieldKind::Password => {
            schema.insert("type".into(), json!("string"));
            schema.insert("format".into(), json!("password"));
            schema.insert("writeOnly".into(), json!(true));
        }
        FieldKind::Bool => {
            schema.insert("type".into(), json!("boolean"));
        }
        FieldKind::Integer { min, max } => {
            schema.insert("type".into(), json!("integer"));
            schema.insert("minimum".into(), json!(min));
            schema.insert("maximum".into(), json!(max));
        }
        FieldKind::Select { options } => {
            schema.insert("type".into(), json!("string"));
            schema.insert("enum".into(), json!(options.iter().map(|o| o.value).collect::<Vec<_>>()));
            schema.insert(
                "x-havuz-labels".into(),
                json!(options.iter().map(|o| json!({ "value": o.value, "label": o.label })).collect::<Vec<_>>()),
            );
        }
        FieldKind::Duration => {
            schema.insert("type".into(), json!("string"));
            schema.insert("format".into(), json!("duration"));
            schema.insert("pattern".into(), json!(r"^\d+(ms|s|m|h|d)$"));
        }
    }

    if let Some(default) = field.default {
        // Keep the JSON type of `default` consistent with the declared type so
        // form libraries do not have to coerce it.
        let typed = match field.kind {
            FieldKind::Integer { .. } => default.parse::<i64>().map(Value::from).unwrap_or_else(|_| json!(default)),
            FieldKind::Bool => default.parse::<bool>().map(Value::from).unwrap_or_else(|_| json!(default)),
            _ => json!(default),
        };
        schema.insert("default".into(), typed);
    }
    if let Some(help) = field.help {
        schema.insert("description".into(), json!(help));
    }
    if let Some(placeholder) = field.placeholder {
        schema.insert("x-havuz-placeholder".into(), json!(placeholder));
    }
    if field.secret {
        schema.insert("x-havuz-secret".into(), json!(true));
    }

    Value::Object(schema)
}

#[cfg(test)]
mod tests {
    use crate::{families, family};

    #[test]
    fn postgres_schema_shape() {
        let pg = family("postgres").unwrap();
        let schema = pg.json_schema();

        assert_eq!(schema["type"], "object");
        assert_eq!(schema["$id"], "havuz:family/postgres");

        let required: Vec<&str> = schema["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required.contains(&"host"), "host must be required");
        assert!(!required.contains(&"port"), "port has a default so it is not required");

        // Order is preserved for the form renderer.
        let order: Vec<&str> =
            schema["x-havuz-order"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(order.first(), Some(&"host"));

        assert_eq!(schema["properties"]["port"]["type"], "integer");
        assert_eq!(schema["properties"]["port"]["default"], 5432, "integer default keeps its JSON type");
        assert_eq!(schema["properties"]["password"]["writeOnly"], true);
        assert_eq!(schema["properties"]["password"]["x-havuz-secret"], true);
        assert!(schema["properties"]["sslmode"]["enum"].as_array().unwrap().iter().any(|v| v == "verify-full"));
    }

    #[test]
    fn every_family_produces_valid_schema() {
        for family in families() {
            let schema = family.json_schema();
            assert_eq!(schema["type"], "object", "{} schema is malformed", family.id);
            assert!(schema["properties"].is_object());
            assert!(schema["required"].is_array());
        }
    }
}
