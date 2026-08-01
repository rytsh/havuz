//! Connection form fields.
//!
//! A family declares its fields once; the UI renders them and havuz validates
//! submitted values against the same declaration. There is no second copy of
//! this knowledge in the frontend.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SelectOption {
    pub value: &'static str,
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    /// Rendered masked; never echoed back by the admin API.
    Password,
    Bool,
    Integer {
        min: i64,
        max: i64,
    },
    Select {
        options: &'static [SelectOption],
    },
    /// humantime string such as `30s` or `5m`.
    Duration,
}

/// What a field means to the pooler, as opposed to what it is called.
///
/// Field *names* belong to the family — `host` here, `jdbc_url` there — but the
/// pooler needs to know a handful of things about every pool regardless: where
/// to connect, as what, and with which credential. Declaring that here is what
/// lets the admin API assemble a [`havuz_core`-style] pool from a form it has
/// never seen, and is why adding a family does not touch the frontend.
///
/// Before this existed the dashboard hardcoded five Postgres field names when
/// submitting the form, so "adding a family never touches the frontend" was
/// true of the rendering and false of the submitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRole {
    /// Hostname or address havuz connects to. For a bridge, the sidecar.
    Host,
    /// TCP port that goes with [`FieldRole::Host`].
    Port,
    /// Database, schema or namespace opened on the backend.
    Database,
    /// Backend service account. Not a client's havuz user.
    User,
    /// Backend credential. Always sealed, never returned.
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConfigField {
    pub name: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
    pub required: bool,
    pub default: Option<&'static str>,
    pub help: Option<&'static str>,
    pub placeholder: Option<&'static str>,
    /// Value is routed to the encrypted secret store, never to state JSON.
    pub secret: bool,
    /// What the pooler should do with this value, if anything. `None` means the
    /// field is family-specific and is simply stored in `settings`.
    pub role: Option<FieldRole>,
}

impl ConfigField {
    /// The same field with its `required` flag cleared.
    ///
    /// Requiredness is a property of the family *and* of how the pool is
    /// configured: a backend service account is the only way in under shared
    /// auth, and just a fallback under per-user auth, where every client brings
    /// its own credential. The registry has no notion of pool modes and should
    /// not grow one, so the caller that does know relaxes the field instead.
    pub fn optional(self) -> Self {
        Self { required: false, ..self }
    }

    /// Validate a submitted value.
    ///
    /// `None` means the field was omitted, which is only an error when the
    /// field is required *and* has no default to fall back on.
    pub fn validate(&self, value: Option<&serde_json::Value>) -> Result<(), FieldError> {
        let Some(value) = value else {
            if self.required && self.default.is_none() {
                return Err(FieldError::Missing { field: self.name });
            }
            return Ok(());
        };

        if value.is_null() {
            if self.required && self.default.is_none() {
                return Err(FieldError::Missing { field: self.name });
            }
            return Ok(());
        }

        match self.kind {
            FieldKind::Text | FieldKind::Password => {
                let s = value.as_str().ok_or(FieldError::WrongType { field: self.name, expected: "string" })?;
                if self.required && s.is_empty() {
                    return Err(FieldError::Missing { field: self.name });
                }
                Ok(())
            }
            FieldKind::Bool => {
                value.as_bool().ok_or(FieldError::WrongType { field: self.name, expected: "boolean" })?;
                Ok(())
            }
            FieldKind::Integer { min, max } => {
                let n = value.as_i64().ok_or(FieldError::WrongType { field: self.name, expected: "integer" })?;
                if n < min || n > max {
                    return Err(FieldError::OutOfRange { field: self.name, min, max, got: n });
                }
                Ok(())
            }
            FieldKind::Select { options } => {
                let s = value.as_str().ok_or(FieldError::WrongType { field: self.name, expected: "string" })?;
                if options.iter().any(|o| o.value == s) {
                    Ok(())
                } else {
                    Err(FieldError::NotAllowed { field: self.name, got: s.to_string() })
                }
            }
            FieldKind::Duration => {
                let s =
                    value.as_str().ok_or(FieldError::WrongType { field: self.name, expected: "duration string" })?;
                parse_duration(s).map(|_| ()).ok_or(FieldError::BadDuration { field: self.name, got: s.to_string() })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FieldError {
    #[error("'{field}' is required")]
    Missing { field: &'static str },
    #[error("'{field}' must be a {expected}")]
    WrongType { field: &'static str, expected: &'static str },
    #[error("'{field}' must be between {min} and {max}, got {got}")]
    OutOfRange { field: &'static str, min: i64, max: i64, got: i64 },
    #[error("'{field}' does not accept the value '{got}'")]
    NotAllowed { field: &'static str, got: String },
    #[error("'{field}' is not a valid duration: '{got}'")]
    BadDuration { field: &'static str, got: String },
}

/// Minimal humantime-style parser: `250ms`, `30s`, `5m`, `2h`, `1d`.
///
/// Deliberately not a dependency — the grammar we accept in config is tiny and
/// we want identical behaviour on both sides of the API.
pub fn parse_duration(input: &str) -> Option<std::time::Duration> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let split = input.find(|c: char| c.is_ascii_alphabetic())?;
    let (value, unit) = input.split_at(split);
    let value: u64 = value.trim().parse().ok()?;
    let millis = match unit.trim() {
        "ms" => value,
        "s" | "sec" => value.checked_mul(1_000)?,
        "m" | "min" => value.checked_mul(60_000)?,
        "h" | "hr" => value.checked_mul(3_600_000)?,
        "d" => value.checked_mul(86_400_000)?,
        _ => return None,
    };
    Some(std::time::Duration::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOST: ConfigField = ConfigField {
        name: "host",
        label: "Host",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: None,
        placeholder: None,
        secret: false,
        role: Some(FieldRole::Host),
    };

    const PORT: ConfigField = ConfigField {
        name: "port",
        label: "Port",
        kind: FieldKind::Integer { min: 1, max: 65535 },
        required: true,
        default: Some("5432"),
        help: None,
        placeholder: None,
        secret: false,
        role: Some(FieldRole::Port),
    };

    const SSLMODE: ConfigField = ConfigField {
        name: "sslmode",
        label: "SSL mode",
        kind: FieldKind::Select {
            options: &[
                SelectOption { value: "disable", label: "disable" },
                SelectOption { value: "require", label: "require" },
            ],
        },
        required: false,
        default: Some("require"),
        help: None,
        placeholder: None,
        secret: false,
        role: None,
    };

    #[test]
    fn required_field_rejects_absence_and_empty_string() {
        assert_eq!(HOST.validate(None), Err(FieldError::Missing { field: "host" }));
        assert_eq!(HOST.validate(Some(&json!(""))), Err(FieldError::Missing { field: "host" }));
        assert_eq!(HOST.validate(Some(&json!("db.internal"))), Ok(()));
    }

    #[test]
    fn a_relaxed_field_accepts_absence_and_nothing_else_changes() {
        let relaxed = HOST.optional();
        assert_eq!(relaxed.validate(None), Ok(()));
        assert_eq!(relaxed.validate(Some(&json!(""))), Ok(()));
        assert_eq!(
            relaxed.validate(Some(&json!(7))),
            Err(FieldError::WrongType { field: "host", expected: "string" }),
            "relaxing requiredness must not relax the type"
        );
    }

    #[test]
    fn required_field_with_default_may_be_omitted() {
        assert_eq!(PORT.validate(None), Ok(()));
    }

    #[test]
    fn integer_range_is_enforced() {
        assert_eq!(PORT.validate(Some(&json!(5432))), Ok(()));
        assert_eq!(
            PORT.validate(Some(&json!(0))),
            Err(FieldError::OutOfRange { field: "port", min: 1, max: 65535, got: 0 })
        );
        assert_eq!(
            PORT.validate(Some(&json!("5432"))),
            Err(FieldError::WrongType { field: "port", expected: "integer" })
        );
    }

    #[test]
    fn select_only_accepts_declared_options() {
        assert_eq!(SSLMODE.validate(Some(&json!("require"))), Ok(()));
        assert_eq!(
            SSLMODE.validate(Some(&json!("verify-full"))),
            Err(FieldError::NotAllowed { field: "sslmode", got: "verify-full".into() })
        );
    }

    #[test]
    fn duration_grammar() {
        use std::time::Duration;
        assert_eq!(parse_duration("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86_400)));
        assert_eq!(parse_duration("30"), None, "unit is mandatory");
        assert_eq!(parse_duration("30x"), None);
        assert_eq!(parse_duration(""), None);
    }
}
