<script lang="ts">
  import { api, formatFanIn } from "../lib/api";
  import type { Pool, Warning } from "../lib/types";
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
    editListenPort = pool.listen_port ?? undefined;
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
        listen_port: editListenPort || null,
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
            <div class="muted text-xs">{pool.database} as {pool.backend_user}</div>
          </td>
          <td>
            {#if pool.listen_port}
              <span class="badge ok">dedicated :{pool.listen_port}</span>
            {:else}
              <span class="muted">shared listener</span>
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
          </td>
          <td>{pool.limits.max_client_connections} → {pool.limits.max_size}</td>
          <td>
            {#if pool.configured_fan_in === null}
              <span class="muted" title="Session mode cannot multiplex">—</span>
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
          <label for="edit-listen-port">Dedicated port <span class="muted font-normal">(optional)</span></label>
          <input id="edit-listen-port" type="number" min="1" max="65535" bind:value={editListenPort} placeholder="shared" />
        </div>
      </div>
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
