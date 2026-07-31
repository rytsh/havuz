//! PostgreSQL family descriptor.
//!
//! One wire protocol, many products. Each profile below is served by the same
//! `havuz-pg` driver; only the quirk flags differ. This is why a single driver
//! covers most of what competitors advertise as separate "database support".

use crate::field::{ConfigField, FieldKind, SelectOption};
use crate::{Capabilities, DriverProfile, FamilyDescriptor, Maturity, PoolMode, Quirks};

pub(crate) const POSTGRES: FamilyDescriptor = FamilyDescriptor {
    id: "postgres",
    label: "PostgreSQL",
    description: "PostgreSQL wire protocol v3. Also covers CockroachDB, Redshift, YugabyteDB and openGauss.",
    maturity: Maturity::Beta,
    default_port: 5432,
    capabilities: Capabilities {
        tls: true,
        scram_sha256: true,
        md5_auth: true,
        prepared_statements: true,
        cancel_request: true,
        bulk_copy: true,
        reports_transaction_status: true,
        listen_notify: true,
        advisory_locks: true,
    },
    pool_modes: &[PoolMode::Session, PoolMode::Transaction, PoolMode::Statement],
    // Session mode is the phase 1 default: it is the only mode we can serve
    // correctly today, and it never silently breaks client expectations.
    default_pool_mode: PoolMode::Session,
    profiles: PROFILES,
    config_fields: FIELDS,
};

const PROFILES: &[DriverProfile] = &[
    DriverProfile {
        id: "postgres",
        label: "PostgreSQL",
        maturity: Maturity::Beta,
        default_port: None,
        quirks: Quirks::POSTGRES,
    },
    DriverProfile {
        id: "cockroachdb",
        label: "CockroachDB",
        maturity: Maturity::Experimental,
        default_port: Some(26257),
        quirks: Quirks {
            supports_discard_all: true,
            // CockroachDB has no advisory locks and no LISTEN/NOTIFY, so those
            // pin reasons can never fire here.
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            max_pool_mode: PoolMode::Transaction,
        },
    },
    DriverProfile {
        id: "redshift",
        label: "Amazon Redshift",
        maturity: Maturity::Experimental,
        default_port: Some(5439),
        quirks: Quirks {
            // Redshift forked from PostgreSQL 8.0 and rejects DISCARD ALL; the
            // pool must fall back to targeted resets when recycling.
            supports_discard_all: false,
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            max_pool_mode: PoolMode::Transaction,
        },
    },
    DriverProfile {
        id: "yugabytedb",
        label: "YugabyteDB",
        maturity: Maturity::Experimental,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: true,
            supports_advisory_locks: true,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            max_pool_mode: PoolMode::Transaction,
        },
    },
    DriverProfile {
        id: "opengauss",
        label: "openGauss / GaussDB",
        maturity: Maturity::Experimental,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: true,
            supports_advisory_locks: true,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            // openGauss negotiates a non-standard SHA256 auth variant, so we
            // stay in session mode until that path is proven.
            max_pool_mode: PoolMode::Session,
        },
    },
];

const SSL_MODES: &[SelectOption] = &[
    SelectOption { value: "disable", label: "disable - no TLS" },
    SelectOption { value: "prefer", label: "prefer - TLS if offered" },
    SelectOption { value: "require", label: "require - TLS, no certificate check" },
    SelectOption { value: "verify-ca", label: "verify-ca - verify chain only" },
    SelectOption { value: "verify-full", label: "verify-full - verify chain and hostname" },
];

const FIELDS: &[ConfigField] = &[
    ConfigField {
        name: "host",
        label: "Host",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: None,
        placeholder: Some("pg-primary.internal"),
        secret: false,
    },
    ConfigField {
        name: "port",
        label: "Port",
        kind: FieldKind::Integer { min: 1, max: 65535 },
        required: true,
        default: Some("5432"),
        help: None,
        placeholder: None,
        secret: false,
    },
    ConfigField {
        name: "database",
        label: "Database",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: Some("Database havuz opens backend connections against."),
        placeholder: Some("appdb"),
        secret: false,
    },
    ConfigField {
        name: "username",
        label: "Backend user",
        kind: FieldKind::Text,
        required: true,
        default: None,
        help: Some("Service account havuz uses. Clients authenticate with their own havuz users, not this one."),
        placeholder: Some("app"),
        secret: false,
    },
    ConfigField {
        name: "password",
        label: "Backend password",
        kind: FieldKind::Password,
        required: false,
        default: None,
        help: Some("Stored encrypted. Never returned by the API."),
        placeholder: None,
        secret: true,
    },
    ConfigField {
        name: "sslmode",
        label: "SSL mode",
        kind: FieldKind::Select { options: SSL_MODES },
        required: false,
        default: Some("prefer"),
        help: Some("Matches libpq semantics. verify-ca checks the chain but not the hostname."),
        placeholder: None,
        secret: false,
    },
    ConfigField {
        name: "ssl_root_cert",
        label: "CA certificate path",
        kind: FieldKind::Text,
        required: false,
        default: None,
        help: Some("PEM bundle used for verify-ca and verify-full. Falls back to the system roots."),
        placeholder: Some("/etc/havuz/tls/ca.pem"),
        secret: false,
    },
    ConfigField {
        name: "connect_timeout",
        label: "Connect timeout",
        kind: FieldKind::Duration,
        required: false,
        default: Some("5s"),
        help: None,
        placeholder: None,
        secret: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldError;
    use serde_json::json;

    fn field(name: &str) -> &'static ConfigField {
        FIELDS.iter().find(|f| f.name == name).expect("field exists")
    }

    #[test]
    fn password_is_marked_secret_so_it_never_lands_in_state_json() {
        assert!(field("password").secret);
        assert!(matches!(field("password").kind, FieldKind::Password));
        // Everything else must not be secret, otherwise the UI masks it.
        for f in FIELDS.iter().filter(|f| f.name != "password") {
            assert!(!f.secret, "{} should not be secret", f.name);
        }
    }

    #[test]
    fn sslmode_covers_all_libpq_values_we_implement() {
        let FieldKind::Select { options } = field("sslmode").kind else {
            panic!("sslmode must be a select");
        };
        let values: Vec<&str> = options.iter().map(|o| o.value).collect();
        assert_eq!(values, ["disable", "prefer", "require", "verify-ca", "verify-full"]);
    }

    #[test]
    fn required_fields_are_the_ones_we_cannot_guess() {
        let required: Vec<&str> = FIELDS.iter().filter(|f| f.required && f.default.is_none()).map(|f| f.name).collect();
        assert_eq!(required, ["host", "database", "username"]);
    }

    #[test]
    fn field_validation_rejects_a_bad_form_submission() {
        assert_eq!(field("host").validate(None), Err(FieldError::Missing { field: "host" }));
        assert!(field("port").validate(Some(&json!(70_000))).is_err());
        assert!(field("connect_timeout").validate(Some(&json!("5s"))).is_ok());
        assert!(field("connect_timeout").validate(Some(&json!("5 seconds"))).is_err());
    }

    #[test]
    fn no_profile_claims_a_mode_the_family_does_not_offer() {
        for profile in PROFILES {
            assert!(
                POSTGRES.pool_modes.contains(&profile.quirks.max_pool_mode),
                "{} allows a mode the family does not list",
                profile.id
            );
        }
    }
}
