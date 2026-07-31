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
mod postgres;
mod schema;

pub use field::{ConfigField, FieldKind, SelectOption};

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
    /// Extended query protocol with named prepared statements. If true, a
    /// transaction-mode pool needs a statement rewriter to be usable.
    pub prepared_statements: bool,
    /// Out-of-band query cancellation on a side channel (PG CancelRequest).
    pub cancel_request: bool,
    /// Bulk streaming mode that must bypass message-level inspection.
    pub bulk_copy: bool,
    /// Server reports transaction state on the wire, so we can detect
    /// boundaries without parsing SQL.
    pub reports_transaction_status: bool,
    pub listen_notify: bool,
    pub advisory_locks: bool,
}

impl Capabilities {
    pub const NONE: Capabilities = Capabilities {
        tls: false,
        scram_sha256: false,
        md5_auth: false,
        prepared_statements: false,
        cancel_request: false,
        bulk_copy: false,
        reports_transaction_status: false,
        listen_notify: false,
        advisory_locks: false,
    };
}

/// A concrete product inside a wire-protocol family.
///
/// The Postgres family covers CockroachDB, Redshift, YugabyteDB and friends:
/// same wire protocol, different quirks. Naming follows dbx's `driver_profile`
/// so connection profiles stay interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub maturity: Maturity,
    /// Overrides the family default when the product listens elsewhere.
    pub default_port: Option<u16>,
    pub quirks: Quirks,
}

/// Per-product deviations from the family baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl Quirks {
    pub const POSTGRES: Quirks = Quirks {
        supports_discard_all: true,
        supports_advisory_locks: true,
        supports_listen_notify: true,
        supports_prepared_statements: true,
        max_pool_mode: PoolMode::Transaction,
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
}

/// Everything havuz knows how to describe.
///
/// `Planned` entries are intentional: they let the UI show the roadmap without
/// pretending a driver exists. Nothing dispatches on this list at runtime — the
/// pool engine resolves behaviour through `havuz_proto::ProtocolFamily`.
static FAMILIES: &[FamilyDescriptor] = &[postgres::POSTGRES, MYSQL_PLANNED, REDIS_PLANNED, JDBC_PLANNED];

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
        },
    }],
    config_fields: &[],
};

const JDBC_PLANNED: FamilyDescriptor = FamilyDescriptor {
    id: "jdbc",
    label: "JDBC bridge",
    description: "Long-tail databases through a JDBC sidecar process. Planned for phase 5.",
    maturity: Maturity::Planned,
    default_port: 0,
    capabilities: Capabilities::NONE,
    pool_modes: &[PoolMode::Session],
    default_pool_mode: PoolMode::Session,
    profiles: &[DriverProfile {
        id: "generic",
        label: "Generic JDBC",
        maturity: Maturity::Planned,
        default_port: None,
        quirks: Quirks {
            supports_discard_all: false,
            supports_advisory_locks: false,
            supports_listen_notify: false,
            supports_prepared_statements: false,
            max_pool_mode: PoolMode::Session,
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
