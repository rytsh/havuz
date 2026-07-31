<script lang="ts">
  import { api, formatMicros } from "../lib/api";
  import type { ActiveTrace, TraceDetail, TraceResponse, TraceSummary } from "../lib/types";

  let data = $state<TraceResponse | null>(null);
  let detail = $state<TraceDetail | null>(null);
  let error = $state<string | null>(null);
  let loadingDetail = $state(false);
  let clearing = $state(false);

  let search = $state("");
  let pool = $state("");
  let user = $state("");
  let status = $state("");
  let minDuration = $state("");

  const pools = $derived(
    [...new Set([...(data?.active ?? []).map((trace) => trace.pool), ...(data?.traces ?? []).map((trace) => trace.pool)])].sort(),
  );
  const users = $derived(
    [...new Set([...(data?.active ?? []).map((trace) => trace.user), ...(data?.traces ?? []).map((trace) => trace.user)])].sort(),
  );
  const visibleActive = $derived(
    (data?.active ?? []).filter(
      (trace) =>
        (!pool || trace.pool === pool) &&
        (!user || trace.user === user) &&
        (!search || `${trace.sql} ${trace.application ?? ""}`.toLowerCase().includes(search.toLowerCase())),
    ),
  );

  function params(): URLSearchParams {
    const value = new URLSearchParams({ limit: "200" });
    if (search) value.set("q", search);
    if (pool) value.set("pool", pool);
    if (user) value.set("user", user);
    if (status) value.set("status", status);
    if (minDuration) value.set("min_duration_ms", minDuration);
    return value;
  }

  async function refresh() {
    try {
      data = await api.traces(params());
      error = null;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }

  async function openTrace(trace: TraceSummary) {
    loadingDetail = true;
    try {
      detail = await api.trace(trace.id);
      error = null;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      loadingDetail = false;
    }
  }

  async function clearHistory() {
    if (!confirm("Delete all completed query traces? Active queries are not affected.")) return;
    clearing = true;
    try {
      await api.clearTraces();
      detail = null;
      await refresh();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      clearing = false;
    }
  }

  function applyFilters(event: Event) {
    event.preventDefault();
    refresh();
  }

  function resetFilters() {
    search = "";
    pool = "";
    user = "";
    status = "";
    minDuration = "";
    refresh();
  }

  function timestamp(value: number): string {
    return new Date(value).toLocaleString();
  }

  function elapsed(trace: ActiveTrace): string {
    return formatMicros(trace.elapsed_us);
  }

  $effect(() => {
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => clearInterval(timer);
  });
</script>

<div class="page-heading">
  <div>
    <div class="eyebrow">Wire-level observability</div>
    <h1>Query trace</h1>
    <p class="subtitle">Every query, who issued it, where it ran, how long it waited, and what PostgreSQL returned.</p>
  </div>
  <div class="row">
    <span class="badge">{data?.retention_days ?? 7} day retention</span>
    <button class="action danger" disabled={clearing} onclick={clearHistory}>Clear history</button>
  </div>
</div>

{#if error}<div class="error">{error}</div>{/if}

<form class="trace-filters" onsubmit={applyFilters}>
  <div class="field mb-0">
    <label for="trace-search">SQL or application</label>
    <input id="trace-search" type="search" bind:value={search} placeholder="orders, SELECT, migration…" />
  </div>
  <div class="field mb-0">
    <label for="trace-pool">Pool</label>
    <select id="trace-pool" bind:value={pool}>
      <option value="">All pools</option>
      {#each pools as name}<option value={name}>{name}</option>{/each}
    </select>
  </div>
  <div class="field mb-0">
    <label for="trace-user">User</label>
    <select id="trace-user" bind:value={user}>
      <option value="">All users</option>
      {#each users as name}<option value={name}>{name}</option>{/each}
    </select>
  </div>
  <div class="field mb-0">
    <label for="trace-status">Status</label>
    <select id="trace-status" bind:value={status}>
      <option value="">All statuses</option>
      <option value="succeeded">Succeeded</option>
      <option value="failed">Failed</option>
      <option value="cancelled">Cancelled</option>
    </select>
  </div>
  <div class="field mb-0">
    <label for="trace-duration">Minimum ms</label>
    <input id="trace-duration" type="number" min="0" bind:value={minDuration} placeholder="0" />
  </div>
  <div class="row self-end">
    <button class="action primary" type="submit">Apply</button>
    <button class="action" type="button" onclick={resetFilters}>Reset</button>
  </div>
</form>

<div class="trace-section-heading">
  <div>
    <div class="eyebrow">Live</div>
    <h2>Running now</h2>
  </div>
  <span class="live-count">{visibleActive.length}</span>
</div>

{#if visibleActive.length === 0}
  <div class="trace-empty">No query is running right now.</div>
{:else}
  <div class="active-traces">
    {#each visibleActive as trace (trace.id)}
      <article class="active-trace">
        <div class="active-trace-top">
          <span class="badge" class:warn={trace.phase === "waiting"} class:ok={trace.phase === "running"}>{trace.phase}</span>
          <span class="trace-clock">{elapsed(trace)}</span>
        </div>
        <pre>{trace.sql}</pre>
        <div class="trace-meta">
          <span><strong>{trace.user}</strong> / {trace.application ?? "unknown app"}</span>
          <span>{trace.pool}</span>
          <span>{trace.client_addr}</span>
          <span>{trace.target ?? "waiting for backend"}</span>
          {#if trace.backend_pid}<span>PID {trace.backend_pid}</span>{/if}
        </div>
      </article>
    {/each}
  </div>
{/if}

<div class="trace-section-heading">
  <div>
    <div class="eyebrow">SQLite history</div>
    <h2>Completed queries</h2>
  </div>
  <span class="muted text-xs">Latest {data?.traces.length ?? 0} records</span>
</div>

{#if data && data.traces.length > 0}
  <table class="trace-table">
    <thead>
      <tr><th>Time</th><th>Query</th><th>Caller</th><th>Pool / target</th><th>Wait</th><th>Total</th><th>Result</th><th></th></tr>
    </thead>
    <tbody>
      {#each data.traces as trace (trace.id)}
        <tr class="cursor-pointer" onclick={() => openTrace(trace)}>
          <td class="whitespace-nowrap muted">{timestamp(trace.started_at_ms)}</td>
          <td><code class="trace-sql">{trace.sql}</code></td>
          <td><strong>{trace.user}</strong><div class="muted text-[11px]">{trace.application ?? trace.client_addr}</div></td>
          <td>{trace.pool}<div class="muted text-[11px]">{trace.target ?? "—"}</div></td>
          <td>{formatMicros(trace.wait_us)}</td>
          <td><strong>{formatMicros(trace.duration_us)}</strong></td>
          <td>
            <span class="badge" class:ok={trace.status === "succeeded"} class:danger={trace.status === "failed"}>{trace.status}</span>
            <div class="muted mt-1 text-[11px]">{trace.command_tag ?? trace.error_code ?? "—"}</div>
          </td>
          <td><button class="action" disabled={loadingDetail}>Inspect</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
{:else}
  <div class="trace-empty">No completed query matches these filters.</div>
{/if}

{#if detail}
  <div class="trace-detail-backdrop" role="presentation" onclick={() => (detail = null)}>
    <div
      class="trace-detail"
      role="dialog"
      aria-modal="true"
      aria-label="Query trace detail"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.key === "Escape" && (detail = null)}
    >
      <div class="trace-detail-head">
        <div>
          <div class="eyebrow">Trace #{detail.id}</div>
          <h2>Query result</h2>
        </div>
        <button class="action" onclick={() => (detail = null)}>Close</button>
      </div>
      <pre class="trace-detail-sql">{detail.sql}</pre>
      <div class="trace-detail-metrics">
        <div><span>Total</span><strong>{formatMicros(detail.duration_us)}</strong></div>
        <div><span>Pool wait</span><strong>{formatMicros(detail.wait_us)}</strong></div>
        <div><span>Execution</span><strong>{formatMicros(detail.execution_us)}</strong></div>
        <div><span>Rows</span><strong>{detail.row_count}</strong></div>
      </div>
      <div class="trace-meta mb-5">
        <span>{detail.user} / {detail.application ?? "unknown app"}</span><span>{detail.client_addr}</span>
        <span>{detail.target ?? "unknown target"}</span>{#if detail.backend_pid}<span>PID {detail.backend_pid}</span>{/if}
      </div>
      {#if detail.error_message}
        <div class="error"><strong>{detail.error_code}</strong> {detail.error_message}</div>
      {/if}
      {#if detail.result_truncated}
        <div class="warning">Result sample reached the {data?.result_limits.rows ?? 100} row or size limit and was truncated.</div>
      {/if}
      {#each detail.result.sets as result, index}
        <div class="result-heading"><span>Result set {index + 1}</span><code>{result.command_tag ?? "rows"}</code></div>
        {#if result.rows.length > 0}
          <div class="result-scroll">
            <table class="result-table">
              <thead><tr>{#each result.columns as column}<th>{column}</th>{/each}</tr></thead>
              <tbody>
                {#each result.rows as row}
                  <tr>{#each row as cell}<td class:null-cell={cell === null}>{cell ?? "NULL"}</td>{/each}</tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      {/each}
      {#if detail.result.sets.length === 0 && !detail.error_message}<div class="trace-empty">The query returned no result set.</div>{/if}
    </div>
  </div>
{/if}
