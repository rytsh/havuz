//! havuz: a PostgreSQL connection pooler with a dashboard.

mod cli;
mod families;
mod listener;
mod pooler;
mod shutdown;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use havuz_control::{ClientGate, Registries};
use havuz_core::{Bootstrap, StateStore};
use havuz_secrets::MasterKey;

use cli::Command;

fn main() -> Result<()> {
    match cli::parse(std::env::args().skip(1))? {
        Command::Help => {
            println!("{}", cli::USAGE);
            Ok(())
        }
        Command::Version => {
            println!("havuz {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Keygen => {
            // Only the key goes to stdout, so `export KEY=$(havuz keygen)` is
            // safe. Base64 padding contains '=', which makes the tempting
            // `KEY=value` output format silently truncate under `cut -d=`.
            let key = MasterKey::generate();
            println!("{}", key.to_base64());
            eprintln!(
                "\nGenerated a master key. Use it with:\n\
                 \n    export {}='{}'\n\
                 \nStore it safely: without it every stored credential is unrecoverable.",
                MasterKey::ENV_VAR,
                key.to_base64()
            );
            Ok(())
        }
        Command::Check { config } => {
            let bootstrap = Bootstrap::load(&config).with_context(|| format!("loading {}", config.display()))?;
            println!("config ok");
            println!("  pool ports bound on {}", bootstrap.server.bind);
            println!("  admin listens on    {}", bootstrap.admin.listen);
            println!("  state directory   {}", bootstrap.state.dir.display());
            Ok(())
        }
        Command::Run { config } => run(config),
    }
}

fn run(config_path: std::path::PathBuf) -> Result<()> {
    let bootstrap = if config_path.exists() {
        Bootstrap::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?
    } else {
        eprintln!("no config at {}, using defaults", config_path.display());
        let defaults = Bootstrap::default();
        defaults.validate()?;
        defaults
    };

    init_tracing(&bootstrap);

    let workers = if bootstrap.server.workers == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        bootstrap.server.workers
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .thread_name("havuz")
        .build()
        .context("building the tokio runtime")?;

    runtime.block_on(serve(bootstrap))
}

async fn serve(bootstrap: Bootstrap) -> Result<()> {
    havuz_core::tls::install_default_provider();

    let master_key = match MasterKey::from_env() {
        Ok(key) => key,
        Err(e) => {
            // Failing here is deliberate. Generating a key silently would make
            // every restart lose the credentials sealed under the previous one.
            bail!("{e}\n\nGenerate one with:  havuz keygen\nThen export it before starting havuz.");
        }
    };
    let master_key = Arc::new(master_key);

    let state_file = bootstrap.state.state_file();
    let store =
        Arc::new(StateStore::open(&state_file).await.with_context(|| format!("opening {}", state_file.display()))?);

    let stale = store.load().secrets.stale_refs(&master_key).len();
    if stale > 0 {
        tracing::warn!(count = stale, "secrets sealed under a different master key; they cannot be read");
    }

    // One session list, one pin rate, one trace database, however many
    // protocols end up running in this process.
    let registries =
        Registries::persistent(bootstrap.state.dir.join("traces.sqlite3")).context("opening query trace store")?;

    // Which families exist is the registry's decision, not this file's.
    let tls = families::client_tls(&bootstrap.server.tls)?;
    let families = families::build(&store, &master_key, &registries, &tls)?;
    families.sync_all().map_err(|e| anyhow::anyhow!("building pools: {e}"))?;

    let current = store.load();
    for warning in current.warnings() {
        tracing::warn!(?warning, "configuration warning");
    }
    let listeners = current.listeners();
    tracing::info!(pools = current.pools.len(), users = current.users.len(), ports = listeners.len(), "state loaded");

    let shutdown = shutdown::Shutdown::new();
    let gate = Arc::new(ClientGate::new(bootstrap.server.max_client_connections));

    let admin_state = havuz_admin::AdminState::new(
        store.clone(),
        master_key.clone(),
        families.clone(),
        registries,
        bootstrap.server.reserved_port(bootstrap.admin.listen),
        tls.acceptor.is_some(),
        &bootstrap.admin.auth,
        bootstrap.admin.ui,
    );

    let admin = listener::spawn_admin(bootstrap.admin.listen, havuz_admin::router(admin_state), shutdown.clone());
    let pooler = tokio::spawn(
        pooler::Pooler::new(
            bootstrap.server.bind,
            bootstrap.server.reserved_port(bootstrap.admin.listen),
            families,
            store.clone(),
            gate,
            shutdown.clone(),
        )
        .run(),
    );

    shutdown.wait_for_signal().await;
    tracing::info!("shutting down, waiting for in-flight sessions");

    let _ = tokio::join!(admin, pooler);
    tracing::info!("goodbye");
    Ok(())
}

fn init_tracing(bootstrap: &Bootstrap) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&bootstrap.log.filter));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if bootstrap.log.json {
        builder.json().init();
    } else {
        builder.init();
    }
}
