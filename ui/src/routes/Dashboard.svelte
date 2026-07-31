<script lang="ts">
  import { api, formatDuration, formatFanIn, formatMicros } from "../lib/api";
  import type { Summary } from "../lib/types";
  import Warnings from "../components/Warnings.svelte";

  let summary = $state<Summary | null>(null);
  let error = $state<string | null>(null);

  async function refresh() {
    try {
      summary = await api.summary();
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    refresh();
    // Polling rather than SSE for now: the payload is tiny and a poll cannot
    // wedge the server behind a slow consumer.
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  });
</script>

<h1>Dashboard</h1>
<p class="subtitle">Live view of what havuz is doing right now.</p>

{#if error}
  <div class="error">{error}</div>
{/if}

{#if summary}
  <div class="cards">
    <div class="card hero">
      <div class="label">Fan-in</div>
      <div class="value">{formatFanIn(summary.fan_in)}</div>
      <div class="hint">clients served per backend connection</div>
    </div>
    <div class="card">
      <div class="label">Client connections</div>
      <div class="value">{summary.client_connections}</div>
    </div>
    <div class="card">
      <div class="label">Backend connections</div>
      <div class="value">{summary.backend_connections}</div>
      <div class="hint">what the database sees</div>
    </div>
    <div class="card">
      <div class="label">Databases</div>
      <div class="value">{summary.pools}</div>
    </div>
    <div class="card">
      <div class="label">Users</div>
      <div class="value">{summary.users}</div>
    </div>
    <div class="card">
      <div class="label">Uptime</div>
      <div class="value">{formatDuration(summary.uptime_seconds)}</div>
    </div>
  </div>

  <Warnings warnings={summary.warnings} />

  <h2>Pools</h2>
  {#if summary.pool_snapshots.length === 0}
    <p class="muted">No pools are running yet. Add a database to get started.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Pool</th>
          <th>Status</th>
          <th>Active</th>
          <th>Idle</th>
          <th>Waiting</th>
          <th>Max</th>
          <th>Checkouts</th>
          <th>Timeouts</th>
          <th>Wait mean</th>
          <th>Wait max</th>
        </tr>
      </thead>
      <tbody>
        {#each summary.pool_snapshots as p (p.name)}
          <tr>
            <td><strong>{p.name}</strong></td>
            <td><span class="badge" class:ok={p.status === "active"}>{p.status}</span></td>
            <td>{p.active}</td>
            <td>{p.idle}</td>
            <td>
              {#if p.waiting > 0}
                <span class="badge warn">{p.waiting}</span>
              {:else}
                0
              {/if}
            </td>
            <td class="muted">{p.max_size}</td>
            <td>{p.checkout_total}</td>
            <td>
              {#if p.timeout_total > 0}
                <span class="badge danger">{p.timeout_total}</span>
              {:else}
                0
              {/if}
            </td>
            <td class="muted">{formatMicros(p.wait.mean_micros)}</td>
            <td class="muted">{formatMicros(p.wait.max_micros)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{:else if !error}
  <p class="muted">Loading…</p>
{/if}
