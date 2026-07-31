<script lang="ts">
  import { push } from "svelte-spa-router";
  import { api, formatMicros } from "../lib/api";
  import type { ActiveTrace, BackendHolder, TraceDetail, TraceResponse, TraceSummary } from "../lib/types";

  let { params: routeParams = {} }: { params?: Record<string, string> } = $props();

  let data = $state<TraceResponse | null>(null);
  let detail = $state<TraceDetail | null>(null);
  let error = $state<string | null>(null);
  let loadingDetail = $state(false);
  let clearing = $state(false);
  let copied = $state<string | null>(null);

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
  const visibleHolders = $derived(
    (data?.holders ?? []).filter(
      (holder) =>
        (!pool || holder.pool === pool) &&
        (!user || holder.user === user) &&
        (!search || `${holder.reason} ${holder.application ?? ""}`.toLowerCase().includes(search.toLowerCase())),
    ),
  );
  const failedCount = $derived((data?.traces ?? []).filter((trace) => trace.status === "failed").length);
  const averageDuration = $derived(
    data?.traces.length ? Math.round(data.traces.reduce((sum, trace) => sum + trace.duration_us, 0) / data.traces.length) : 0,
  );
  const totalRows = $derived((data?.traces ?? []).reduce((sum, trace) => sum + trace.row_count, 0));

  function queryParams(): URLSearchParams {
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
      data = await api.traces(queryParams());
      error = null;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }

  async function openTrace(trace: TraceSummary) {
    await push(`/trace/${trace.id}`);
  }

  async function loadTrace(id: number) {
    loadingDetail = true;
    try {
      detail = await api.trace(id);
      error = null;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      loadingDetail = false;
    }
  }

  async function closeDetail() {
    detail = null;
    await push("/trace");
  }

  async function copyText(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      copied = key;
      setTimeout(() => {
        if (copied === key) copied = null;
      }, 1400);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : "Clipboard access failed";
    }
  }

  function csvCell(value: unknown): string {
    if (value === null || value === undefined) return "";
    let text = String(value);
    if (/^[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replaceAll('"', '""')}"`;
  }

  function download(name: string, content: string, type: string) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function exportHistory() {
    const header = ["time", "status", "pool", "user", "application", "client", "target", "wait_us", "execution_us", "total_us", "rows", "sql"];
    const rows = (data?.traces ?? []).map((trace) => [
      new Date(trace.started_at_ms).toISOString(), trace.status, trace.pool, trace.user, trace.application,
      trace.client_addr, trace.target, trace.wait_us, trace.execution_us, trace.duration_us, trace.row_count, trace.sql,
    ]);
    download("havuz-query-history.csv", [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n"), "text/csv;charset=utf-8");
  }

  function exportResultCsv() {
    if (!detail) return;
    const sections = detail.result.sets.map((result, index) => {
      const title = [csvCell(`Result set ${index + 1}`), csvCell(result.command_tag)].join(",");
      const header = result.columns.map(csvCell).join(",");
      const rows = result.rows.map((row) => row.map(csvCell).join(","));
      return [title, header, ...rows].join("\n");
    });
    download(`havuz-trace-${detail.id}.csv`, sections.join("\n\n"), "text/csv;charset=utf-8");
  }

  function exportResultJson() {
    if (!detail) return;
    download(`havuz-trace-${detail.id}.json`, JSON.stringify(detail, null, 2), "application/json");
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

  function holderAdvice(holder: BackendHolder): { title: string; detail: string } {
    switch (holder.reason) {
      case "startup_wait":
        return {
          title: "Waiting to start",
          detail: "Authentication succeeded, but every backend slot is occupied. This connection can hit queue_timeout.",
        };
      case "session_mode":
        return {
          title: "Reserved by session mode",
          detail: "This client owns one backend until it disconnects, even when it is not running a query.",
        };
      case "idle_in_transaction":
        return {
          title: "Idle in transaction",
          detail: "The last query finished, but COMMIT or ROLLBACK has not arrived, so the backend cannot be released.",
        };
      case "pinned":
        return {
          title: `Pinned: ${holder.pin_reason ?? "unknown"}`,
          detail: "Session-scoped state prevents this backend from being shared until the client disconnects.",
        };
    }
  }

  $effect(() => {
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => clearInterval(timer);
  });

  $effect(() => {
    const id = Number(routeParams.id);
    if (Number.isInteger(id) && id > 0 && detail?.id !== id) loadTrace(id);
    if (!routeParams.id) detail = null;
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
    <button class="action" disabled={!data?.traces.length} onclick={exportHistory}>Export history CSV</button>
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

{#if data?.pool_snapshots.length}
  <div class="pressure-grid">
    {#each data.pool_snapshots as snapshot (snapshot.name)}
      <article class:hot={snapshot.waiting > 0 || snapshot.active >= snapshot.max_size}>
        <div class="pressure-head"><strong>{snapshot.name}</strong><span>{snapshot.active}/{snapshot.max_size} active</span></div>
        <div class="pressure-bar"><i style={`width:${Math.min(100, (snapshot.active / Math.max(1, snapshot.max_size)) * 100)}%`}></i></div>
        <div class="pressure-meta">
          <span>{snapshot.waiting} waiting</span><span>{snapshot.idle} idle</span><span>{snapshot.timeout_total} timeouts</span>
        </div>
      </article>
    {/each}
  </div>
{/if}

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
    <div class="eyebrow">Pool blockers</div>
    <h2>Backend holders</h2>
  </div>
  <span class="live-count" class:has-blockers={visibleHolders.length > 0}>{visibleHolders.length}</span>
</div>

{#if visibleHolders.length === 0}
  <div class="trace-empty">No idle client is holding or waiting for a backend slot.</div>
{:else}
  <div class="holder-grid">
    {#each visibleHolders as holder (holder.id)}
      {@const advice = holderAdvice(holder)}
      <article class="holder-card" class:waiting={holder.reason === "startup_wait"}>
        <div class="holder-top">
          <div><span class="badge warn">{advice.title}</span><strong>{holder.user}</strong></div>
          <span class="trace-clock">{formatMicros(holder.elapsed_us)}</span>
        </div>
        <p>{advice.detail}</p>
        <div class="trace-meta">
          <span>{holder.application ?? "unknown app"}</span><span>{holder.pool}</span><span>{holder.client_addr}</span>
          {#if holder.target}<span>{holder.target}</span>{/if}{#if holder.backend_pid}<span>PID {holder.backend_pid}</span>{/if}
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

<div class="history-summary">
  <div><span>Displayed</span><strong>{data?.traces.length ?? 0}</strong></div>
  <div><span>Failed</span><strong class:danger-text={failedCount > 0}>{failedCount}</strong></div>
  <div><span>Average time</span><strong>{formatMicros(averageDuration)}</strong></div>
  <div><span>Rows affected</span><strong>{totalRows}</strong></div>
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
          <td>
            <div class="trace-query-cell">
              <code class="trace-sql">{trace.sql}</code>
              <button
                class="copy-button"
                title="Copy query"
                onclick={(event) => { event.stopPropagation(); copyText(trace.sql, `row-${trace.id}`); }}
              >{copied === `row-${trace.id}` ? "Copied" : "Copy"}</button>
            </div>
          </td>
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
  <div class="trace-detail-backdrop" role="presentation" onclick={closeDetail}>
    <div
      class="trace-detail"
      role="dialog"
      aria-modal="true"
      aria-label="Query trace detail"
      tabindex="-1"
      onclick={(event) => event.stopPropagation()}
      onkeydown={(event) => event.key === "Escape" && closeDetail()}
    >
      <div class="trace-detail-head">
        <div>
          <div class="eyebrow">Trace #{detail.id}</div>
          <h2>Query result</h2>
        </div>
        <div class="row">
          <button class="action" onclick={() => detail && copyText(detail.sql, "detail-query")}>{copied === "detail-query" ? "Copied" : "Copy query"}</button>
          <button class="action" disabled={detail.result.sets.length === 0} onclick={exportResultCsv}>Export CSV</button>
          <button class="action" onclick={exportResultJson}>Export JSON</button>
          <button class="action" onclick={closeDetail}>Close</button>
        </div>
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
