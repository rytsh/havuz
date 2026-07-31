<script lang="ts">
  import { api } from "../lib/api";
  import type { GroupSnapshot, Pool, PrimaryReason } from "../lib/types";

  let pools = $state<Pool[]>([]);
  let selected = $state<string | null>(null);
  let group = $state<GroupSnapshot | null>(null);
  let error = $state<string | null>(null);

  /**
   * Why a statement went to the primary. Without this, "my replicas are idle"
   * has no answer — and the answer is usually a configuration choice rather
   * than a broken replica.
   */
  const reasonLabel: Record<PrimaryReason, string> = {
    split_disabled: "read/write split is off for this pool",
    write: "the statement writes",
    read_after_write: "the session wrote recently, so its reads follow it",
    transaction_pinned: "inside a transaction that started on the primary",
    no_replica_available: "no replica was healthy and caught up",
  };

  async function refresh() {
    try {
      pools = (await api.pools()).pools;
      if (!selected && pools.length > 0) selected = pools[0].name;
      group = selected ? await api.poolTargets(selected) : null;
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  function breakerClass(state: string): string {
    return state === "closed" ? "ok" : state === "half_open" ? "warn" : "danger";
  }

  function lagLabel(millis: number | null): string {
    // Never measured is not the same as caught up, and the difference decides
    // whether the replica is used at all.
    if (millis === null) return "not measured";
    if (millis < 1000) return `${millis} ms`;
    return `${(millis / 1000).toFixed(1)} s`;
  }

  const nonZeroReasons = $derived((group?.routing.primary_reasons ?? []).filter((r) => r.count > 0));

  $effect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  });
</script>

<h1>Targets</h1>
<p class="subtitle">Replica health, replication lag, and where statements actually went.</p>

{#if error}
  <div class="error">{error}</div>
{/if}

{#if pools.length === 0}
  <p class="muted">No pools configured.</p>
{:else}
  <div class="field" style="max-width:280px">
    <label for="pool-select">Pool</label>
    <select id="pool-select" bind:value={selected} onchange={refresh}>
      {#each pools as pool (pool.name)}
        <option value={pool.name}>{pool.name}</option>
      {/each}
    </select>
  </div>
{/if}

{#if group}
  {#if !group.read_write_split}
    <div class="warning">
      <strong>Read/write split is off for this pool.</strong>
      <div>
        Every statement goes to the primary. Turning it on changes what your application sees: a read issued right after
        a write can be served by a replica that has not caught up. havuz keeps such reads on the primary for the sticky
        window, which is what makes the split safe for ordinary applications.
      </div>
    </div>
  {/if}

  <div class="cards">
    <div class="card" class:hero={(group.routing.replica_share ?? 0) > 0}>
      <div class="label">Served by replicas</div>
      <div class="value">
        {group.routing.replica_share === null ? "—" : `${(group.routing.replica_share * 100).toFixed(0)}%`}
      </div>
      <div class="hint">of routed statements</div>
    </div>
    <div class="card">
      <div class="label">To primary</div>
      <div class="value">{group.routing.to_primary}</div>
    </div>
    <div class="card">
      <div class="label">To replicas</div>
      <div class="value">{group.routing.to_replica}</div>
    </div>
  </div>

  <h2>Targets</h2>
  <table>
    <thead>
      <tr>
        <th>Address</th>
        <th>Role</th>
        <th>Health</th>
        <th>Lag</th>
        <th>Weight</th>
        <th>Connections</th>
        <th>Trips</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>{group.primary.label}</strong></td>
        <td><span class="badge ok">primary</span></td>
        <td><span class="badge ok">serving</span></td>
        <td class="muted">—</td>
        <td class="muted">—</td>
        <td>{group.primary.pool.active} active / {group.primary.pool.idle} idle</td>
        <td class="muted">—</td>
      </tr>
      {#each group.replicas as replica (replica.label)}
        <tr>
          <td><strong>{replica.label}</strong></td>
          <td><span class="badge">replica</span></td>
          <td>
            <span class="badge {breakerClass(replica.breaker.state)}">{replica.breaker.state}</span>
          </td>
          <td class:muted={replica.lag_millis === null}>{lagLabel(replica.lag_millis)}</td>
          <td>{replica.weight}</td>
          <td>{replica.pool.active} active / {replica.pool.idle} idle</td>
          <td>
            {#if replica.breaker.trips_total > 0}
              <span class="badge danger">{replica.breaker.trips_total}</span>
            {:else}
              0
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if group.replicas.length === 0}
    <p class="muted" style="margin-top:10px">
      This pool has no replicas. Add targets with role <code>replica</code> to spread reads.
    </p>
  {/if}

  {#if nonZeroReasons.length > 0}
    <h2>Why statements went to the primary</h2>
    <table>
      <thead>
        <tr><th>Reason</th><th>Count</th><th>Meaning</th></tr>
      </thead>
      <tbody>
        {#each nonZeroReasons as row (row.reason)}
          <tr>
            <td><code>{row.reason}</code></td>
            <td><strong>{row.count}</strong></td>
            <td class="muted">{reasonLabel[row.reason]}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}
