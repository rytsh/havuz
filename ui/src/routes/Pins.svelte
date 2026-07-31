<script lang="ts">
  import { api } from "../lib/api";
  import type { PinReport, PinReason } from "../lib/types";

  let report = $state<PinReport | null>(null);
  let error = $state<string | null>(null);
  let hideUnactionable = $state(true);

  /**
   * What an operator can actually do about each reason. This is the difference
   * between telemetry and advice — a count of "session_parameter: 412" is not
   * useful unless you also know it usually comes from a driver setting.
   */
  const advice: Record<PinReason, string> = {
    session_parameter:
      "A SET havuz cannot replay onto another backend. Ordinary SETs are carried over automatically and cost nothing; this is one of the exceptions — SET ROLE, SET SESSION AUTHORIZATION, a value supplied through a bind parameter, or a SET issued inside an open transaction. Use SET LOCAL inside transactions, and set the role on the pool's backend account rather than per session.",
    listen: "LISTEN makes the connection a notification target, so it can never be shared. Use a dedicated connection outside the pool for listeners.",
    temp_table: "Temporary tables live in a per-connection schema. Consider an unlogged table, or a CTE.",
    advisory_lock: "Session-level advisory locks outlive the transaction. pg_advisory_xact_lock does not, and is safe here.",
    server_side_prepare: "PREPARE creates a session-scoped statement. Use the driver's parameterised queries instead.",
    holdable_cursor: "A cursor declared WITH HOLD survives commit. Drop WITH HOLD, or fetch the rows in one go.",
    bulk_transfer: "COPY takes over the connection for its duration. Expected and unavoidable for bulk loads.",
    replication: "Replication connections are inherently exclusive. Nothing to fix.",
    unclassified: "havuz could not classify this and pinned to stay safe. Please report the statement.",
  };

  async function refresh() {
    try {
      report = await api.pins();
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function reset() {
    if (!confirm("Reset pin statistics? Do this after deploying a fix to confirm it worked.")) return;
    await api.resetPins();
    await refresh();
  }

  const visible = $derived(
    (report?.offenders ?? []).filter((o) => !hideUnactionable || o.actionable),
  );

  const nonZeroReasons = $derived((report?.by_reason ?? []).filter((r) => r.count > 0));

  function ratePercent(rate: number | null): string {
    return rate === null ? "—" : `${(rate * 100).toFixed(1)}%`;
  }

  $effect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  });
</script>

<h1>Pin analysis</h1>
<p class="subtitle">
  A pinned session holds its backend until the client disconnects, so it cannot be multiplexed. This is the usual reason
  a transaction-mode pool does not deliver the fan-in it was configured for.
</p>

{#if error}
  <div class="error">{error}</div>
{/if}

{#if report}
  <div class="cards">
    <div class="card" class:hero={(report.pin_rate ?? 0) > 0.05}>
      <div class="label">Pin rate</div>
      <div class="value">{ratePercent(report.pin_rate)}</div>
      <div class="hint">of transaction-mode sessions</div>
    </div>
    <div class="card">
      <div class="label">Pinned</div>
      <div class="value">{report.pinned_sessions}</div>
    </div>
    <div class="card">
      <div class="label">Shareable</div>
      <div class="value">{report.clean_sessions}</div>
    </div>
  </div>

  {#if report.pinned_sessions === 0}
    <p class="muted">
      No sessions have been pinned. Either nothing is running in transaction mode yet, or your clients are behaving —
      in which case the configured fan-in is real.
    </p>
  {:else}
    {#if (report.pin_rate ?? 0) > 0.05}
      <div class="warning">
        <strong>More than 5% of sessions are pinned.</strong>
        <div>
          Those sessions each hold a backend for their whole lifetime, so the pool is behaving closer to session mode
          than to transaction mode. The table below shows exactly which client and which construct is responsible.
        </div>
      </div>
    {/if}

    <h2>By reason</h2>
    <div class="table-scroll">
    <table>
      <thead>
        <tr><th>Reason</th><th>Sessions</th><th>What to do</th></tr>
      </thead>
      <tbody>
        {#each nonZeroReasons as row (row.reason)}
          <tr>
            <td><code>{row.reason}</code></td>
            <td><strong>{row.count}</strong></td>
            <td class="muted">{advice[row.reason]}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>

    <h2>
      By client
      <label class="ml-3 text-xs font-normal">
        <input type="checkbox" bind:checked={hideUnactionable} />
        only what can be fixed
      </label>
    </h2>

    {#if visible.length === 0}
      <p class="muted">Nothing actionable. Every remaining pin comes from something that cannot be avoided.</p>
    {:else}
      <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Application</th>
            <th>Reason</th>
            <th>Sessions</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {#each visible as o (o.user + o.application + o.reason)}
            <tr>
              <td><strong>{o.user}</strong></td>
              <td>{o.application}</td>
              <td>
                <code>{o.reason}</code>
                {#if !o.actionable}<span class="badge">unavoidable</span>{/if}
              </td>
              <td>{o.count}</td>
              <td class="muted">{o.last_seen_secs_ago}s ago</td>
            </tr>
          {/each}
        </tbody>
      </table>
      </div>
    {/if}

    {#if report.truncated}
      <p class="muted mt-2.5">
        Per-client detail was capped to keep memory bounded. The counts by reason above remain exact.
      </p>
    {/if}

    <button class="action mt-4" onclick={reset}>Reset statistics</button>
  {/if}
{:else if !error}
  <p class="muted">Loading…</p>
{/if}
