//! Protocol family registry.
//!
//! Every database family havuz can pool is described here as **data**, not as
//! scattered `match db_type { .. }` arms. The admin UI renders its "Add
//! Database" forms straight from [`FamilyDescriptor::json_schema`], which means
//! adding a new family never requires touching the frontend.
//!
//! Behaviour lives behind `havuz_proto::ProtocolFamily`; this crate only carries
//! the static metadata needed to *describe* and *configure* a family.

mod field;
mod jdbc;
mod postgres;
mod schema;
mod session;

pub use field::{ConfigField, FieldError, FieldKind, FieldRole, SelectOption};
pub use session::{PinReason, PinRule, SessionRules};

use serde::{Deserialize, Serialize};

/// Maturity of a family or profile. Drives UI badges and lets us ship
/// "coming soon" cards without shipping half-working drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Maturity {
    Stable,
    Beta,
    Experimental,
    /// Visible in the UI as a disabled card. No driver is compiled in.
    Planned,
}

impl Maturity {
    pub fn is_usable(self) -> bool {
        !matches!(self, Maturity::Planned)
    }
}

/// How aggressively havuz may hand a backend connection to another client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolMode {
    /// Backend is owned by the client until it disconnects. Fan-in is 1:1.
    Session,
    /// Backend is released at every transaction boundary. This is where the
    /// 100-clients-to-3-backends win actually happens.
    Transaction,
    /// Backend is released after every statement. Explicit transactions are
    /// rejected.
    Statement,
}

impl PoolMode {
    /// Whether this mode can actually multiplex clients over fewer backends.
    ///
    /// The UI uses this to warn when someone sets `max_size = 3` on a session
    /// mode pool and wonders why 97 clients are queued.
    pub fn multiplexes(self) -> bool {
        matches!(self, PoolMode::Transaction | PoolMode::Statement)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PoolMode::Session => "session",
            PoolMode::Transaction => "transaction",
            PoolMode::Statement => "statement",
        }
    }
}

/// What the wire protocol supports. Used by the pool engine and surfaced to the
/// UI so a family's limits are visible in one place instead of being spread
/// across predicate functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Server supports an in-band TLS upgrade (e.g. PG's SSLRequest).
    pub tls: bool,
    pub scram_sha256: bool,
    pub md5_auth: bool,
    /// Backend connections can be opened as the connecting client rather than
    /// as a shared service account. Needs a handshake that can ask the client
    /// for a password havuz is able to replay upstream, which is not something
    /// every family's driver offers. False means `backend_auth = per_user` is
    /// refused rather than silently ignored.
    pub per_user_auth: bool,
    /// Extended query protocol with named prepared statements. If true, a
    /// transaction-mode pool needs a statement rewriter to be usable.
    pub prepared_statements: bool,
    /// A session can be opened read-only and held that way.
    ///
    /// Needs two things the driver has to supply together: a way to tell the
    /// server "refuse writes on this session" — PostgreSQL's
    /// `default_transaction_read_only` — and enough of a view of the traffic to
    /// stop the client turning it off again. A family with only the first has a
    /// suggestion, not a restriction.
    ///
    /// False means `read_only` is refused on the pool rather than accepted and
    /// ignored. An operator who ticks a box called read-only and gets a pool
    /// that writes is worse off than one who was told no.
    pub read_only_sessions: bool,
    /// Out-of-band query cancellation on a side channel (PG CancelRequest).
    pub cancel_request: bool,
    /// Bulk streaming mode that must bypass message-level inspection.
    pub bulk_copy: bool,
    /// Server reports transaction state on the wire, so we can detect
    /// boundaries without parsing SQL.
    pub reports_transaction_status: bool,
    pub listen_notify: bool,
    pub advisory_locks: bool,
    /// The driver understands statements well enough to decide for itself which
    /// ones leave state behind.
    ///
    /// Not a property of the wire protocol but of what havuz can do with it,
    /// and it belongs next to the other limits because it decides the same
    /// thing they do: whether a pooling mode is offered. False means the
    /// product must supply [`Quirks::session`] rules before it may exceed
    /// [`PoolMode::Session`], because a family that cannot tell a `SELECT` from
    /// an `ALTER SESSION` cannot promise a released backend is clean.
    pub classifies_statements: bool,
}

impl Capabilities {
    pub const NONE: Capabilities = Capabilities {
        tls: false,
        scram_sha256: false,
        md5_auth: false,
        per_user_auth: false,
        prepared_statements: false,
        read_only_sessions: false,
        cancel_request: false,
        bulk_copy: false,
        reports_transaction_status: false,
        listen_notify: false,
        advisory_locks: false,
        classifies_statements: false,
    };
}

/// A concrete product inside a wire-protocol family.
///
/// The Postgres family covers CockroachDB, Redshift, YugabyteDB and friends:
/// same wire protocol, different quirks. Naming follows dbx's `driver_profile`
/// so connection profiles stay interchangeable.
///
/// Serialize but not Deserialize, here and on [`Quirks`]: every field is
/// `&'static`, so a round trip could only ever produce data that leaked. The
/// admin API reads these out; nothing writes them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DriverProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub maturity: Maturity,
    /// Overrides the family default when the product listens elsewhere.
    pub default_port: Option<u16>,
    pub quirks: Quirks,
}

/// Per-product deviations from the family baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Quirks {
    /// `DISCARD ALL` is understood. CockroachDB and Redshift are not fully
    /// compatible here, so we fall back to targeted resets.
    pub supports_discard_all: bool,
    pub supports_advisory_locks: bool,
    pub supports_listen_notify: bool,
    /// Server-side prepared statements behave like upstream Postgres.
    pub supports_prepared_statements: bool,
    /// Highest pooling mode considered safe for this product.
    pub max_pool_mode: PoolMode,
    /// What this product's statements do to the state a connection carries,
    /// and how to clear it.
    ///
    /// Only read by families that cannot classify statements themselves; see
    /// [`Capabilities::classifies_statements`].
    pub session: SessionRules,
}

impl Quirks {
    pub const POSTGRES: Quirks = Quirks {
        supports_discard_all: true,
        supports_advisory_locks: true,
        supports_listen_notify: true,
        supports_prepared_statements: true,
        max_pool_mode: PoolMode::Transaction,
        // `havuz-pg` classifies statements itself and resets with `DISCARD
        // ALL`, so nothing here would ever be read. Stating the reset query
        // anyway would put a second source of truth next to the first.
        session: SessionRules::OPAQUE,
    };
}

/// The static description of one wire-protocol family.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FamilyDescriptor {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub maturity: Maturity,
    pub default_port: u16,
    pub capabilities: Capabilities,
    pub pool_modes: &'static [PoolMode],
    pub default_pool_mode: PoolMode,
    pub profiles: &'static [DriverProfile],
    /// Connection form fields. The UI renders these; havuz validates against them.
    pub config_fields: &'static [ConfigField],
}

impl FamilyDescriptor {
    pub fn profile(&self, id: &str) -> Option<&'static DriverProfile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// Profile to use when the operator did not pick one explicitly.
    pub fn default_profile(&self) -> &'static DriverProfile {
        self.profiles.first().expect("every family declares at least one profile")
    }

    /// Effective listen port for a profile.
    pub fn port_for(&self, profile: Option<&str>) -> u16 {
        profile.and_then(|id| self.profile(id)).and_then(|p| p.default_port).unwrap_or(self.default_port)
    }

    /// JSON Schema for the connection form. See [`schema`] for the shape.
    pub fn json_schema(&self) -> serde_json::Value {
        schema::build(self)
    }

    /// The field carrying a given role, if this family declares one.
    pub fn field_for(&self, role: FieldRole) -> Option<&'static ConfigField> {
        self.config_fields.iter().find(|field| field.role == Some(role))
    }

    /// Pull the pooler-level facts out of a submitted connection form.
    ///
    /// The caller does not have to know that Postgres spells the account
    /// `username` and something else spells it `user`: the family declared
    /// which field means what, and this reads it back. Missing required values
    /// are the validator's problem, not this function's, so anything absent
    /// comes back empty.
    pub fn connection(&self, settings: &serde_json::Map<String, serde_json::Value>) -> Connection {
        let text = |role: FieldRole| -> Option<String> {
            let field = self.field_for(role)?;
            match settings.get(field.name) {
                Some(serde_json::Value::String(value)) => Some(value.clone()),
                Some(serde_json::Value::Number(value)) => Some(value.to_string()),
                _ => field.default.map(str::to_string),
            }
        };

        Connection {
            host: text(FieldRole::Host).unwrap_or_default(),
            port: text(FieldRole::Port).and_then(|value| value.parse().ok()).unwrap_or(self.default_port),
            database: text(FieldRole::Database).unwrap_or_default(),
            user: text(FieldRole::User).unwrap_or_default(),
            password: text(FieldRole::Password).filter(|value| !value.is_empty()),
        }
    }

    /// Field names whose values must not be persisted in plain state.
    pub fn secret_fields(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.config_fields.iter().filter(|field| field.secret).map(|field| field.name)
    }
}

/// Where and as whom havuz opens backend connections for a pool.
///
/// Assembled from the family's own field names via [`FieldRole`], so the admin
/// API can build a pool out of a form it has never seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    /// `None` when the form left it blank, which is not the same as an empty
    /// password: a blank field means "do not change what is stored".
    pub password: Option<String>,
}

/// Everything havuz knows how to describe.
///
/// `Planned` entries are intentional: they let the UI show the roadmap without
/// pretending a driver exists. Nothing dispatches on this list at runtime — the
/// pool engine resolves behaviour through `havuz_proto::ProtocolFamily`.
static FAMILIES: &[FamilyDescriptor] = &[postgres::POSTGRES, jdbc::JDBC, MYSQL_PLANNED, REDIS_PLANNED];

const MYSQL_PLANNED: FamilyDescriptor = FamilyDescriptor {
    id: "mysql",
    label: "MySQL",
    description: "MySQL, MariaDB, TiDB, OceanBase, Doris, StarRocks. Planned for phase 3.",
    maturity: Maturity::Planned,
    default_port: 3306,
    capabilities: Capabilities::NONE,
    pool_modes: &[PoolMode::Session],
    default_pool_mode: PoolMode::Session,
    profiles: &[DriverProfile {
        id: "mysql",
        label: "MySQL",
        maturity: Maturity::Planned,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: false,
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: true,
            max_pool_mode: PoolMode::Session,
            session: SessionRules::OPAQUE,
        },
    }],
    config_fields: &[],
};

const REDIS_PLANNED: FamilyDescriptor = FamilyDescriptor {
    id: "redis",
    label: "Redis",
    description: "RESP protocol proxy with pipelining. Planned for phase 4.",
    maturity: Maturity::Planned,
    default_port: 6379,
    capabilities: Capabilities::NONE,
    pool_modes: &[PoolMode::Session],
    default_pool_mode: PoolMode::Session,
    profiles: &[DriverProfile {
        id: "redis",
        label: "Redis",
        maturity: Maturity::Planned,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: false,
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: false,
            max_pool_mode: PoolMode::Session,
            session: SessionRules::OPAQUE,
        },
    }],
    config_fields: &[],
};

/// All descriptors, including planned ones.
pub fn families() -> &'static [FamilyDescriptor] {
    FAMILIES
}

/// Descriptors backed by a driver that is actually compiled in.
pub fn usable_families() -> impl Iterator<Item = &'static FamilyDescriptor> {
    FAMILIES.iter().filter(|f| f.maturity.is_usable())
}

pub fn family(id: &str) -> Option<&'static FamilyDescriptor> {
    FAMILIES.iter().find(|f| f.id == id)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("unknown database family '{0}'")]
    UnknownFamily(String),
    #[error("family '{family}' has no driver profile '{profile}'")]
    UnknownProfile { family: String, profile: String },
    #[error("family '{0}' is not implemented yet")]
    NotImplemented(String),
    #[error("pool mode '{mode}' is not supported by '{family}'")]
    UnsupportedPoolMode { family: String, mode: &'static str },
}

/// Resolve a family + optional profile, rejecting anything we cannot serve.
pub fn resolve(
    family_id: &str,
    profile_id: Option<&str>,
) -> Result<(&'static FamilyDescriptor, &'static DriverProfile), RegistryError> {
    let family = family(family_id).ok_or_else(|| RegistryError::UnknownFamily(family_id.to_string()))?;
    if !family.maturity.is_usable() {
        return Err(RegistryError::NotImplemented(family_id.to_string()));
    }
    let profile = match profile_id {
        Some(id) => family
            .profile(id)
            .ok_or_else(|| RegistryError::UnknownProfile { family: family_id.to_string(), profile: id.to_string() })?,
        None => family.default_profile(),
    };
    Ok((family, profile))
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    use serde_json::json;

    fn settings(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
    }

    #[test]
    fn a_form_is_read_back_through_roles_not_field_names() {
        let pg = family("postgres").unwrap();
        let connection = pg.connection(&settings(&[
            ("host", json!("pg-primary.internal")),
            ("port", json!(6543)),
            ("database", json!("appdb")),
            ("username", json!("app")),
            ("password", json!("hunter2")),
        ]));

        assert_eq!(
            connection,
            Connection {
                host: "pg-primary.internal".into(),
                port: 6543,
                database: "appdb".into(),
                user: "app".into(),
                password: Some("hunter2".into()),
            }
        );
    }

    #[test]
    fn an_omitted_port_falls_back_to_the_declared_default() {
        let pg = family("postgres").unwrap();
        assert_eq!(pg.connection(&settings(&[("host", json!("db"))])).port, 5432);
    }

    #[test]
    fn a_blank_password_is_absent_rather_than_empty() {
        // An empty string would overwrite a stored credential with nothing.
        let pg = family("postgres").unwrap();
        assert_eq!(pg.connection(&settings(&[("password", json!(""))])).password, None);
        assert_eq!(pg.connection(&settings(&[])).password, None);
    }

    #[test]
    fn secret_fields_are_named_so_they_can_be_kept_out_of_state() {
        let pg = family("postgres").unwrap();
        assert_eq!(pg.secret_fields().collect::<Vec<_>>(), ["password"]);
    }

    #[test]
    fn a_family_without_a_role_reports_nothing_for_it() {
        // A planned family declares no fields at all, which must be a clean
        // empty answer rather than a panic.
        let mysql = family("mysql").unwrap();
        assert!(mysql.field_for(FieldRole::Host).is_none());
        assert_eq!(mysql.connection(&settings(&[])).host, "");
    }

    #[test]
    fn a_family_may_carry_its_address_in_one_field() {
        // A JDBC URL names its own host and port. Splitting them into separate
        // fields would be two places to write the same thing and two places to
        // get it wrong, so the URL takes the host role and there is no port.
        let jdbc = family("jdbc").unwrap();
        assert_eq!(jdbc.field_for(FieldRole::Host).map(|f| f.name), Some("url"));
        assert!(jdbc.field_for(FieldRole::Port).is_none());

        let connection = jdbc
            .connection(&settings(&[("url", json!("jdbc:oracle:thin:@//db:1521/ORCL")), ("username", json!("app"))]));
        assert_eq!(connection.host, "jdbc:oracle:thin:@//db:1521/ORCL");
        assert_eq!(connection.user, "app");
        // No port field and no family default, so nothing is invented.
        assert_eq!(connection.port, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_is_registered_and_usable() {
        let (family, profile) = resolve("postgres", None).expect("postgres must resolve");
        assert_eq!(family.id, "postgres");
        assert_eq!(profile.id, "postgres");
        assert_eq!(family.default_port, 5432);
    }

    #[test]
    fn planned_families_are_visible_but_not_resolvable() {
        assert!(family("mysql").is_some(), "planned families stay visible to the UI");
        assert_eq!(resolve("mysql", None).unwrap_err(), RegistryError::NotImplemented("mysql".into()));
    }

    #[test]
    fn unknown_family_and_profile_are_distinguishable() {
        assert_eq!(resolve("nope", None).unwrap_err(), RegistryError::UnknownFamily("nope".into()));
        assert_eq!(
            resolve("postgres", Some("nope")).unwrap_err(),
            RegistryError::UnknownProfile { family: "postgres".into(), profile: "nope".into() }
        );
    }

    #[test]
    fn profile_port_falls_back_to_family_default() {
        let pg = family("postgres").unwrap();
        assert_eq!(pg.port_for(None), 5432);
        assert_eq!(pg.port_for(Some("redshift")), 5439, "redshift overrides the family port");
        assert_eq!(pg.port_for(Some("cockroachdb")), 26257);
    }

    #[test]
    fn only_multiplexing_modes_report_fan_in() {
        assert!(!PoolMode::Session.multiplexes());
        assert!(PoolMode::Transaction.multiplexes());
        assert!(PoolMode::Statement.multiplexes());
    }

    #[test]
    fn every_family_declares_at_least_one_profile() {
        for family in families() {
            assert!(!family.profiles.is_empty(), "{} has no profiles", family.id);
            assert!(
                family.pool_modes.contains(&family.default_pool_mode),
                "{} default pool mode is not in its supported list",
                family.id
            );
        }
    }

    #[test]
    fn no_profile_claims_a_pooling_mode_its_family_does_not_offer() {
        // The two are independently written and were previously allowed to
        // disagree: `PoolConfig::validate` only ever consulted the profile, so
        // a family could advertise session-only while a profile quietly
        // permitted transaction mode.
        for family in families() {
            for profile in family.profiles {
                assert!(
                    family.pool_modes.contains(&profile.quirks.max_pool_mode),
                    "{}/{} allows {} which the family does not list",
                    family.id,
                    profile.id,
                    profile.quirks.max_pool_mode.as_str()
                );
            }
        }
    }

    #[test]
    fn nothing_multiplexes_without_a_way_to_know_what_a_statement_did() {
        // Releasing a backend between transactions is a promise that it
        // carries nothing from the last client. Either the driver can read
        // statements well enough to make that promise, or the product had to
        // spell out which of its statements are safe. Neither is optional.
        for family in families() {
            for profile in family.profiles {
                if !profile.quirks.max_pool_mode.multiplexes() {
                    continue;
                }
                assert!(
                    family.capabilities.classifies_statements || profile.quirks.session.classifies(),
                    "{}/{} multiplexes but nothing can tell a SELECT from a SET on it",
                    family.id,
                    profile.id
                );
            }
        }
    }

    #[test]
    fn family_ids_and_profile_ids_are_unique() {
        let mut ids: Vec<&str> = families().iter().map(|f| f.id).collect();
        ids.sort_unstable();
        let len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len, "duplicate family id");

        for family in families() {
            let mut pids: Vec<&str> = family.profiles.iter().map(|p| p.id).collect();
            pids.sort_unstable();
            let len = pids.len();
            pids.dedup();
            assert_eq!(pids.len(), len, "duplicate profile id in {}", family.id);
        }
    }
}
