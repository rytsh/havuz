<script lang="ts">
  import { api, formatFanIn } from "../lib/api";
  import type { Pool, Warning } from "../lib/types";
  import Warnings from "../components/Warnings.svelte";

  let pools = $state<Pool[]>([]);
  let warnings = $state<Warning[]>([]);
  let error = $state<string | null>(null);
  let busy = $state<string | null>(null);
  let probes = $state<Record<string, string>>({});

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

  $effect(() => {
    refresh();
  });
</script>

<h1>Databases</h1>
<p class="subtitle">Configured pools and the connection budget each one enforces.</p>

{#if error}
  <div class="error">{error}</div>
{/if}

<Warnings {warnings} />

{#if pools.length === 0}
  <p class="muted">Nothing configured yet. Use “Add database”.</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Name</th>
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
            <div class="muted" style="font-size:11px">{pool.database} as {pool.backend_user}</div>
          </td>
          <td>
            {pool.family}
            {#if pool.profile && pool.profile !== pool.family}
              <div class="muted" style="font-size:11px">{pool.profile}</div>
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
              <div class="muted" style="font-size:11px; margin-top:4px">{probes[pool.name]}</div>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
