<script lang="ts">
  import { api, formatFanIn, parseAliases } from "../lib/api";
  import type { Pool, TraceLevel, Warning } from "../lib/types";
  import Warnings from "../components/Warnings.svelte";
  import PoolModeGuide from "../components/PoolModeGuide.svelte";

  let pools = $state<Pool[]>([]);
  let warnings = $state<Warning[]>([]);
  let error = $state<string | null>(null);
  let busy = $state<string | null>(null);
  let probes = $state<Record<string, string>>({});
  let editing = $state<string | null>(null);
  let editMode = $state<Pool["mode"]>("transaction");
  let editMaxSize = $state(10);
  let editMaxClients = $state(100);
  let editListenPort = $state<number | undefined>(undefined);
  let editAliases = $state("");
  let editTrace = $state<TraceLevel>("statements");
  let editAllowPasswordWithoutTls = $state(false);
  /** Only per-user pools ever ask for a password, so only they can leak one. */
  let editIsPerUser = $state(false);

  const traceLabel: Record<TraceLevel, string> = {
    off: "not traced",
    statements: "queries traced",
    full: "queries + results traced",
  };

  /**
   * Ports serving more than one pool. Worth flagging: on those, a client has
   * to name the pool it wants, and on the others the name is ignored.
   */
  const sharedPorts = $derived(
    new Set(
      pools
        .map((pool) => pool.listen_port)
        .filter((port, _, all) => all.filter((other) => other === port).length > 1),
    ),
  );

  async function refresh() {
    try {
      const result = await api.pools();
      pools = result.pools;
      warnings = result.warnings;
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function act(name: string, fn: () => Promise<unknown>) {
    busy = name;
    try {
      await fn();
      await refresh();
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = null;
    }
  }

  async function probe(name: string) {
    busy = name;
    probes = { ...probes, [name]: "testing…" };
    try {
      const result = await api.probePool(name);
      probes = {
        ...probes,
        [name]: result.ok
          ? `${result.probe?.version ?? "connected"} (${result.probe?.latency_ms ?? 0} ms)`
          : (result.error ?? "failed"),
      };
    } catch (e) {
      probes = { ...probes, [name]: e instanceof Error ? e.message : String(e) };
    } finally {
      busy = null;
    }
  }

  function remove(name: string) {
    if (!confirm(`Delete pool "${name}"? Clients using it will be disconnected.`)) return;
    act(name, () => api.deletePool(name));
  }

  function configure(pool: Pool) {
    editing = pool.name;
    editMode = pool.mode;
    editMaxSize = pool.limits.max_size;
    editMaxClients = pool.limits.max_client_connections;
    editListenPort = pool.listen_port;
    editAliases = pool.aliases.join(", ");
    editTrace = pool.trace;
    editAllowPasswordWithoutTls = pool.allow_password_without_tls;
    editIsPerUser = pool.backend_auth !== "shared";
  }

  async function saveConfiguration(event: Event) {
    event.preventDefault();
    if (!editing) return;
    const name = editing;
    await act(name, () =>
      api.updatePool(name, {
        mode: editMode,
        max_size: editMaxSize,
        max_client_connections: editMaxClients,
        listen_port: editListenPort,
        aliases: parseAliases(editAliases),
        trace: editTrace,
        // Sent only where it means something. On a shared pool the server would
        // store it and nothing would ever read it, which is a worse kind of
        // confusing than not offering it.
        ...(editIsPerUser ? { allow_password_without_tls: editAllowPasswordWithoutTls } : {}),
      }),
    );
    if (!error) editing = null;
  }

  $effect(() => {
    refresh();
  });
</script>

<h1>Databases</h1>

{#if error}
  <div class="error">{error}</div>
{/if}

<Warnings {warnings} />

{#if pools.length === 0}
  <p class="muted">Nothing configured yet. Use “Add database”.</p>
{:else}
  <div class="table-scroll">
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Client endpoint</th>
        <th>Type</th>
        <th>Target</th>
        <th>Mode</th>
        <th>Clients → Backends</th>
        <th>Fan-in</th>
        <th>Live</th>
        <th>Status</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each pools as pool (pool.name)}
        <tr>
          <td>
            <strong>{pool.name}</strong>
            {#if pool.backend_auth !== "shared"}
              <div class="muted text-xs">{pool.database} as each connecting user</div>
              <span class="badge" title="Backend connections are opened with each client's own credentials"
                >per-user auth</span
              >
              {#if pool.backend_auth === "passthrough"}
                <span
                  class="badge warn"
                  title="Clients havuz has no user record for are admitted if the database accepts their credentials, so a first attempt from anyone who can reach this port reaches PostgreSQL's authentication"
                  >passthrough</span
                >
              {/if}
              {#if pool.allow_password_without_tls}
                <span
                  class="badge danger"
                  title="This pool asks for database passwords even without TLS, so anyone on the network path can read them and use them against the database directly"
                  >no TLS required</span
                >
              {/if}
            {:else}
              <div class="muted text-xs">{pool.database} as {pool.backend_user}</div>
            {/if}
          </td>
          <td>
            <span class="badge ok">:{pool.listen_port}</span>
            {#if sharedPorts.has(pool.listen_port)}
              <div class="muted text-xs">shared, selected by name</div>
            {/if}
            {#if pool.aliases.length}
              <div class="muted text-xs" title="Database names that also reach this pool">
                also {pool.aliases.join(", ")}
              </div>
            {/if}
          </td>
          <td>
            {pool.family}
            {#if pool.profile && pool.profile !== pool.family}
              <div class="muted text-xs">{pool.profile}</div>
            {/if}
          </td>
          <td class="muted">{pool.targets.map((t) => `${t.host}:${t.port}`).join(", ")}</td>
          <td>
            <span class="badge" class:ok={pool.mode !== "session"}>{pool.mode}</span>
            <div class="muted text-xs" title="Change under Configure">{traceLabel[pool.trace]}</div>
          </td>
          <td>
            {pool.limits.max_client_connections} → {pool.limits.max_size}
            {#if pool.backend_ceiling === null}
              <div class="muted text-xs" title="max_size is applied to each user separately">per user</div>
            {/if}
          </td>
          <td>
            {#if pool.configured_fan_in === null}
              <span class="muted" title="Session mode cannot multiplex">—</span>
            {:else if pool.backend_auth !== "shared"}
              <strong>{formatFanIn(pool.configured_fan_in)}</strong>
              <div class="muted text-xs" title="Each user multiplexes over its own connections">per user</div>
            {:else}
              <strong>{formatFanIn(pool.configured_fan_in)}</strong>
            {/if}
          </td>
          <td class="muted">
            {#if pool.runtime}
              {pool.runtime.active} active / {pool.runtime.idle} idle
            {:else}
              —
            {/if}
          </td>
          <td>
            {#if pool.disabled}
              <span class="badge warn">paused</span>
            {:else}
              <span class="badge ok">active</span>
            {/if}
          </td>
          <td>
            <div class="row">
              <button class="action" disabled={busy === pool.name} onclick={() => probe(pool.name)}>Test</button>
              <button class="action" disabled={busy === pool.name} onclick={() => configure(pool)}>Configure</button>
              {#if pool.disabled}
                <button class="action" disabled={busy === pool.name} onclick={() => act(pool.name, () => api.resumePool(pool.name))}>
                  Resume
                </button>
              {:else}
                <button class="action" disabled={busy === pool.name} onclick={() => act(pool.name, () => api.pausePool(pool.name))}>
                  Pause
                </button>
              {/if}
              <button class="action danger" disabled={busy === pool.name} onclick={() => remove(pool.name)}>Delete</button>
            </div>
            {#if probes[pool.name]}
              <div class="muted mt-1 text-xs">{probes[pool.name]}</div>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  </div>

  {#if editing}
    <form class="config-panel" onsubmit={saveConfiguration}>
      <div>
        <h2 class="mt-0">Tune {editing}</h2>
        <p class="muted mb-0">New connections use this configuration immediately; established sessions finish on the old one.</p>
      </div>
      <div class="config-grid">
        <div class="field mb-0">
          <label for="edit-mode">Pooling mode</label>
          <select id="edit-mode" bind:value={editMode}>
            <option value="session">session</option>
            <option value="transaction">transaction</option>
            <option value="statement">statement</option>
          </select>
        </div>
        <div class="field mb-0">
          <label for="edit-max-size">Backend connections</label>
          <input id="edit-max-size" type="number" min="1" bind:value={editMaxSize} />
        </div>
        <div class="field mb-0">
          <label for="edit-max-clients">Client connections</label>
          <input id="edit-max-clients" type="number" min="1" bind:value={editMaxClients} />
        </div>
        <div class="field mb-0">
          <label for="edit-listen-port">Client port</label>
          <input id="edit-listen-port" type="number" min="1" max="65535" bind:value={editListenPort} required />
        </div>
        <div class="field mb-0">
          <label for="edit-aliases">Also reachable as</label>
          <input id="edit-aliases" bind:value={editAliases} placeholder="orders, orders_prod" />
        </div>
        <div class="field mb-0">
          <label for="edit-trace">Query tracing</label>
          <select id="edit-trace" bind:value={editTrace}>
            <option value="off">Nothing recorded</option>
            <option value="statements">Queries only</option>
            <option value="full">Queries and their results</option>
          </select>
        </div>
      </div>
      {#if editIsPerUser}
        <div class="field mb-0">
          <label class="font-normal">
            <input type="checkbox" bind:checked={editAllowPasswordWithoutTls} />
            Ask for passwords even without TLS
          </label>
        </div>
      {/if}
      {#if editIsPerUser && editAllowPasswordWithoutTls}
        <div class="warning mb-0">
          This pool asks each client for its <em>database</em> password. With this on it does so even without TLS, so
          anyone who can read the traffic gets a working database credential and can connect directly, past this pool's
          grants and past <code>read_only</code>. Turning it back off is refused while Havuz has no certificate of its
          own — every client would be locked out.
        </div>
      {/if}
      {#if editListenPort !== undefined && !sharedPorts.has(editListenPort) && editAliases.trim()}
        <div class="warning mb-0">
          Nothing else is on port {editListenPort}, so the database name in a connection string is ignored and these
          aliases do nothing yet. They start mattering the moment a second pool joins this port — which is exactly when
          you want them already in place.
        </div>
      {/if}
      {#if editTrace === "full"}
        <div class="warning mb-0">
          Result rows are kept verbatim for as long as the trace retention allows. Turn this back down once you have
          what you needed.
        </div>
      {/if}
      <PoolModeGuide mode={editMode} />
      {#if editMode === "session" && editMaxClients > editMaxSize}
        <div class="warning mb-0">
          Session mode reserves one backend per connected client. The excess clients will wait and receive SQLSTATE
          53300 when the queue timeout expires.
        </div>
      {/if}
      <div class="row">
        <button class="action primary" type="submit" disabled={busy === editing}>Save configuration</button>
        <button class="action" type="button" onclick={() => (editing = null)}>Cancel</button>
      </div>
    </form>
  {/if}
{/if}
