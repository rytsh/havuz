//! Building the families this binary has drivers for.
//!
//! The registry decides which families exist; this module decides which of them
//! this build can actually serve. Those two lists must agree, and a mismatch is
//! a startup error rather than a family that silently never pools anything:
//! a descriptor marked usable with no driver behind it would show an enabled
//! card in the dashboard and then reject every pool created from it.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use havuz_control::{ControlPlane, FamilySet, Registries};
use havuz_core::{ServerTls, StateStore};
use havuz_pg::{ClientTls, PgFamily};
use havuz_registry::FamilyDescriptor;
use havuz_secrets::MasterKey;
use tokio_rustls::TlsAcceptor;

/// Turn the configured certificate into an acceptor the families can use.
///
/// Without this the client-facing leg is plaintext no matter what the config
/// file says. Only the backend leg was ever encrypted, which is a surprising
/// thing for a config file with a `[server.tls]` section to mean.
pub fn client_tls(config: &ServerTls) -> Result<ClientTls> {
    let (Some(cert), Some(key)) = (&config.cert, &config.key) else {
        return Ok(ClientTls::default());
    };
    let server = havuz_core::tls::server_config(cert, key)
        .with_context(|| format!("loading client TLS material from {} and {}", cert.display(), key.display()))?;
    tracing::info!(cert = %cert.display(), "client-facing TLS enabled");
    Ok(ClientTls { acceptor: Some(TlsAcceptor::from(server)), require: config.require_client_cert })
}

/// Construct one family per usable registry descriptor.
///
/// Ordered by the registry, so the result is stable across restarts. Every
/// family shares one set of [`Registries`]: two protocols in one process are
/// still one session list, one pin rate and one trace database.
pub fn build(
    store: &Arc<StateStore>,
    master_key: &Arc<MasterKey>,
    registries: &Registries,
    tls: &ClientTls,
) -> Result<FamilySet> {
    let families = havuz_registry::usable_families()
        .map(|descriptor| build_one(descriptor, store, master_key, registries, tls))
        .collect::<Result<Vec<Arc<dyn ControlPlane>>>>()?;
    if families.is_empty() {
        bail!("no protocol family is compiled into this build");
    }
    Ok(FamilySet::new(families))
}

fn build_one(
    descriptor: &'static FamilyDescriptor,
    store: &Arc<StateStore>,
    master_key: &Arc<MasterKey>,
    registries: &Registries,
    tls: &ClientTls,
) -> Result<Arc<dyn ControlPlane>> {
    match descriptor.id {
        id if id == havuz_pg::FAMILY_ID => {
            Ok(PgFamily::with_tls(store.clone(), master_key.clone(), registries.clone(), tls.clone()))
        }
        id if id == havuz_jdbc::FAMILY_ID => {
            Ok(havuz_jdbc::JdbcFamily::new(store.clone(), master_key.clone(), registries.clone()))
        }
        // Reached only if someone promotes a descriptor out of `Planned`
        // without adding the driver. Failing loudly here is the whole point:
        // the dashboard would otherwise offer a card that rejects every pool.
        other => bail!(
            "family '{other}' is usable in the registry but no driver is compiled into this build; \
             either add the driver or set its maturity back to `planned`"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_core::State;

    fn families() -> FamilySet {
        let key = Arc::new(MasterKey::generate());
        let store = Arc::new(StateStore::ephemeral(State::default()));
        build(&store, &key, &Registries::ephemeral(), &ClientTls::default())
            .expect("every usable family must have a driver")
    }

    /// If this fails, a descriptor was promoted out of `planned` without a
    /// driver, and the dashboard is now offering something that cannot work.
    #[test]
    fn every_usable_registry_family_has_a_driver() {
        let ids: Vec<_> = families().iter().map(|f| f.descriptor().id).collect();
        let expected: Vec<_> = havuz_registry::usable_families().map(|f| f.id).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn no_certificate_means_no_acceptor_rather_than_an_error() {
        // Starting without TLS has to keep working; it is the default.
        assert!(client_tls(&ServerTls::default()).unwrap().acceptor.is_none());
    }

    #[test]
    fn a_family_can_be_found_by_the_id_a_pool_names() {
        assert!(families().get(havuz_pg::FAMILY_ID).is_some());
        assert!(families().get("cassandra").is_none());
    }
}
