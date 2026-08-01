<script lang="ts">
  import { push } from "svelte-spa-router";
  import { iconFor } from "../lib/icons";
  import { api } from "../lib/api";
  import type {
    BackendAuth,
    DriverProfile,
    Family,
    FieldRole,
    PoolMode,
    SchemaProperty,
    TraceLevel,
  } from "../lib/types";
  import PoolModeGuide from "../components/PoolModeGuide.svelte";

  let families = $state<Family[]>([]);
  let selected = $state<Family | null>(null);
  let profileId = $state<string>("");
  let error = $state<string | null>(null);
  let submitting = $state(false);

  // Family-specific values, driven entirely by the schema the server sends.
  let settings = $state<Record<string, unknown>>({});

  let name = $state("");
  let mode = $state<PoolMode>("session");
  let maxSize = $state(10);
  let maxClients = $state(100);
  let listenPort = $state<number | undefined>(undefined);
  let backendAuth = $state<BackendAuth>("shared");

  // Asked as two questions because they are two decisions. Whether to record at
  // all is an operational one; how much to keep is a data-protection one, and
  // collapsing them into a single list hides the second behind the first.
  let tracing = $state<"on" | "off">("on");
  let traceDepth = $state<Exclude<TraceLevel, "off">>("statements");
  const traceLevel = $derived<TraceLevel>(tracing === "off" ? "off" : traceDepth);

  let search = $state("");
  let category = $state("relational");
  let layout = $state<"grid" | "list">("grid");

  const catalog = $derived(
    families.flatMap((family) =>
      family.profiles.map((profile) => ({ family, profile, category: categoryOf(family) })),
    ),
  );
  const visibleCatalog = $derived(
    catalog.filter((item) => {
      const matchesCategory = category === "all" || item.category === category;
      const haystack = `${item.profile.label} ${item.family.label} ${item.family.description}`.toLowerCase();
      return matchesCategory && haystack.includes(search.trim().toLowerCase());
    }),
  );

  const categories = [
    { id: "all", label: "All types" },
    { id: "relational", label: "Relational" },
    { id: "cache", label: "Cache / key-value" },
    { id: "bridge", label: "Bridge" },
  ];

  $effect(() => {
    api
      .families()
      .then((f) => (families = f))
      .catch((e) => (error = e instanceof Error ? e.message : String(e)));
  });

  function categoryOf(family: Family): string {
    if (family.id === "redis") return "cache";
    if (family.id === "jdbc") return "bridge";
    return "relational";
  }

  function pick(family: Family, profile: DriverProfile) {
    if (!family.usable || profile.maturity === "planned") return;
    selected = family;
    profileId = profile.id;
    mode = family.default_pool_mode;
    backendAuth = "shared";
    tracing = "on";
    traceDepth = "statements";
    // Seed defaults straight from the schema so the form starts valid.
    const seeded: Record<string, unknown> = {};
    for (const key of family.schema["x-havuz-order"] ?? []) {
      const prop = family.schema.properties[key];
      if (prop?.default !== undefined) seeded[key] = prop.default;
    }
    const portField = roleField(family, "port");
    if (portField && profile.default_port !== null) seeded[portField] = profile.default_port;
    settings = seeded;
    listenPort = undefined;
  }

  /** The field a family uses for a given pooler role, if it declares one. */
  function roleField(family: Family, role: FieldRole): string | undefined {
    return Object.entries(family.schema.properties).find(([, prop]) => prop["x-havuz-role"] === role)?.[0];
  }

  function backToCatalog() {
    selected = null;
    profileId = "";
    error = null;
  }

  function fieldsOf(family: Family): [string, SchemaProperty][] {
    const order = family.schema["x-havuz-order"] ?? Object.keys(family.schema.properties);
    return order.map((key) => [key, family.schema.properties[key]] as [string, SchemaProperty]);
  }

  /**
   * Credential fields the backend identity choice makes optional.
   *
   * Under per-user auth every client connects with its own password, so the
   * service account is a fallback for probes and unmigrated users rather than
   * the way in. Mirrors the same relaxation the admin API applies, so the form
   * never blocks a submission the server would have accepted.
   */
  const relaxedRoles: FieldRole[] = ["user", "password"];

  function isRequired(family: Family, key: string): boolean {
    if (!(family.schema.required ?? []).includes(key)) return false;
    const role = family.schema.properties[key]?.["x-havuz-role"];
    return !(backendAuth === "per_user" && role !== undefined && relaxedRoles.includes(role));
  }

  /**
   * The number the operator actually cares about. Reported as null in session
   * mode because a client holds its backend for the whole session there, so no
   * amount of arithmetic produces real multiplexing.
   */
  const fanIn = $derived(mode === "session" || maxSize === 0 ? null : maxClients / maxSize);
  const queued = $derived(Math.max(0, maxClients - maxSize));

  async function submit(event: Event) {
    event.preventDefault();
    if (!selected) return;

    submitting = true;
    error = null;

    // The form goes over verbatim. The server reads host, port, database,
    // account and password back out of it through the roles the family
    // declared, so this file never learns what those fields are called.
    const body = {
      name,
      family: selected.id,
      profile: profileId || undefined,
      mode,
      listen_port: listenPort,
      backend_auth: backendAuth,
      trace: traceLevel,
      limits: { max_size: maxSize, max_client_connections: maxClients },
      settings,
    };

    try {
      await api.createPool(body);
      await push("/databases");
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      submitting = false;
    }
  }
</script>

{#if !selected}
  <div class="page-heading connection-heading">
    <div>
      <h1>New database</h1>
      <p class="subtitle">Choose a database type. Havuz will tailor the connection and pooling options.</p>
    </div>
    <a class="action" href="#/databases">Cancel</a>
  </div>

  {#if error}<div class="error">{error}</div>{/if}

  <section class="connection-picker">
    <div class="connection-toolbar">
      <div class="view-switch" aria-label="Catalog layout">
        <button class:active={layout === "grid"} onclick={() => (layout = "grid")} title="Grid view">Grid</button>
        <button class:active={layout === "list"} onclick={() => (layout = "list")} title="List view">List</button>
      </div>
      <label class="connection-search">
        <span>Search</span>
        <input type="search" bind:value={search} placeholder="Search database types" />
      </label>
      <div class="catalog-count">{visibleCatalog.length} database types</div>
    </div>

    <div class="catalog-layout">
      <nav class="catalog-categories" aria-label="Database categories">
        {#each categories as item (item.id)}
          <button class:active={category === item.id} onclick={() => (category = item.id)}>
            <span>{item.label}</span>
            <small>{catalog.filter((entry) => item.id === "all" || entry.category === item.id).length}</small>
          </button>
        {/each}
      </nav>

      <div class="database-catalog" class:list={layout === "list"}>
        {#each visibleCatalog as item (`${item.family.id}:${item.profile.id}`)}
          {@const icon = iconFor(item.profile.id, item.family.id)}
          <button
            class="database-type-card"
            class:available={item.family.usable && item.profile.maturity !== "planned"}
            disabled={!item.family.usable || item.profile.maturity === "planned"}
            onclick={() => pick(item.family, item.profile)}
          >
            <span class="database-mark" style={`--brand:#${icon.hex}`}>
              <svg viewBox="0 0 24 24" role="img" aria-label={icon.title}><path d={icon.path}></path></svg>
            </span>
            <span class="database-card-copy">
              <strong>{item.profile.label}</strong>
              <small>{item.family.usable ? `${item.profile.maturity} driver` : "Coming soon"}</small>
            </span>
            {#if !item.family.usable}<span class="badge">planned</span>{/if}
          </button>
        {:else}
          <div class="catalog-empty">No database type matches “{search}”.</div>
        {/each}
      </div>
    </div>
  </section>
{:else}
  {@const selectedProfile = selected.profiles.find((profile) => profile.id === profileId)}
  <div class="page-heading connection-heading">
    <div>
      <button class="back-link" onclick={backToCatalog}>Back to database types</button>
      <div class="selected-database-title">
        {#if selectedProfile}
          {@const icon = iconFor(selectedProfile.id, selected.id)}
          <span class="database-mark" style={`--brand:#${icon.hex}`}>
            <svg viewBox="0 0 24 24" role="img" aria-label={icon.title}><path d={icon.path}></path></svg>
          </span>
        {/if}
        <h1>{selectedProfile?.label ?? selected.label}</h1>
      </div>
      <p class="subtitle">Configure the upstream database and the client connection budget.</p>
    </div>
  </div>

  {#if error}<div class="error">{error}</div>{/if}

  <form class="connection-form" onsubmit={submit}>
    <section class="form-section">
      <div class="form-section-heading"><span>01</span><div><h2>Connection</h2><p>Where Havuz should reach this database.</p></div></div>
      <div class="form-fields">

    <div class="field">
      <label for="pool-name">Pool name</label>
      <div class="help">Clients connect to this as if it were the database name.</div>
      <input id="pool-name" bind:value={name} required placeholder="app_main" />
    </div>

    <div class="field">
      <label for="listen-port">Client port</label>
      <div class="help">
        The port clients connect to for this pool. Pools may share a port, in which case clients pick between them by
        pool name; a port with a single pool ignores the database name entirely.
      </div>
      <input id="listen-port" type="number" min="1" max="65535" bind:value={listenPort} required placeholder="6432" />
    </div>

    <!-- Rendered from the server's schema: a new family needs no UI change. -->
    {#each fieldsOf(selected) as [key, prop] (key)}
      <div class="field">
        <label for={`f-${key}`}>
          {prop.title ?? key}
          {#if !isRequired(selected, key)}<span class="muted font-normal">(optional)</span>{/if}
        </label>
        {#if prop.description}<div class="help">{prop.description}</div>{/if}

        {#if prop.enum}
          <select id={`f-${key}`} bind:value={settings[key]}>
            {#each prop["x-havuz-labels"] ?? prop.enum.map((v) => ({ value: v, label: v })) as option (option.value)}
              <option value={option.value}>{option.label}</option>
            {/each}
          </select>
        {:else if prop.type === "integer"}
          <input
            id={`f-${key}`}
            type="number"
            min={prop.minimum}
            max={prop.maximum}
            bind:value={settings[key]}
            required={isRequired(selected, key)}
          />
        {:else if prop.type === "boolean"}
          <input id={`f-${key}`} type="checkbox" bind:checked={settings[key] as boolean} />
        {:else}
          <input
            id={`f-${key}`}
            type={prop["x-havuz-secret"] ? "password" : "text"}
            placeholder={prop["x-havuz-placeholder"] ?? ""}
            bind:value={settings[key]}
            required={isRequired(selected, key)}
          />
        {/if}
      </div>
    {/each}
      </div>
    </section>

    <section class="form-section">
      <div class="form-section-heading"><span>02</span><div><h2>Connection budget</h2><p>How client sessions share database backends.</p></div></div>
      <div class="form-fields wide">

    <div class="field">
      <label for="mode">Pooling mode</label>
      <div class="help">Only transaction and statement mode can share a backend between clients.</div>
      <select id="mode" bind:value={mode}>
        {#each selected.pool_modes as m (m)}
          <option value={m}>{m}</option>
        {/each}
      </select>
    </div>

    <PoolModeGuide {mode} />

    {#if selected.capabilities.per_user_auth}
      <div class="field">
        <label for="backend-auth">Backend identity</label>
        <div class="help">
          Who Havuz connects to the database as. A shared service account is what makes one backend connection reusable
          by any client. Connecting as each user instead gives you <code>pg_stat_activity.usename</code>, row-level
          security and real <code>GRANT</code> enforcement, at the cost of a separate set of connections per user.
        </div>
        <select id="backend-auth" bind:value={backendAuth}>
          <option value="shared">One shared service account</option>
          <option value="per_user">Each user, with its own credentials</option>
        </select>
      </div>
    {/if}

    {#if backendAuth === "per_user"}
      <div class="help notice">
        Requires client-facing TLS: Havuz has to ask each client for its password, and will only do so over an encrypted
        connection. Users keep using the service account until you switch them over individually on the Users page.
        The service account itself is optional here — leave it blank and only users connecting as themselves get in,
        at the cost of health probes and <em>Test connection</em>, which have no client credential to borrow.
      </div>
    {/if}

    <div class="field">
      <label for="max-clients">Max client connections</label>
      <input id="max-clients" type="number" min="1" bind:value={maxClients} />
    </div>

    <div class="field">
      <label for="max-size">
        Max backend connections {#if backendAuth === "per_user"}<span class="muted font-normal">(per user)</span>{/if}
      </label>
      <div class="help">
        {#if backendAuth === "per_user"}
          Applied to each user separately, so the total depends on how many are connected at once. PostgreSQL's own
          <code>CONNECTION LIMIT</code> per role is the backstop; this is what gives a client a queue instead of an
          error.
        {:else}
          The number that protects your database.
        {/if}
      </div>
      <input id="max-size" type="number" min="1" bind:value={maxSize} />
    </div>

    <div class="card mb-4 max-w-[460px]">
      {#if fanIn === null}
        <div class="label">Fan-in</div>
        <div class="value">—</div>
        <div class="hint">
          In session mode a client keeps its backend until it disconnects, so
          <strong>{queued}</strong> of your {maxClients} clients would queue and eventually time out. Choose transaction
          mode to actually multiplex.
        </div>
      {:else}
        <div class="label">Fan-in</div>
        <div class="value">{fanIn.toFixed(1)}x</div>
        <div class="hint">{maxClients} clients served by at most {maxSize} backend connections.</div>
      {/if}
    </div>
      </div>
    </section>

    <section class="form-section">
      <div class="form-section-heading">
        <span>03</span>
        <div><h2>Query tracing</h2><p>What havuz keeps about the traffic through this pool.</p></div>
      </div>
      <div class="form-fields wide">

    <div class="field">
      <label for="trace">Record queries</label>
      <div class="help">
        A pooler that cannot say which statement waited, on which backend, and for how long is a black box in the
        middle of your database traffic. Turning this off makes the pool invisible on the <strong>Query trace</strong>
        screen — no history, and no entry under "running now" either.
      </div>
      <select id="trace" bind:value={tracing}>
        <option value="on">Yes, record queries from this pool</option>
        <option value="off">No, record nothing</option>
      </select>
    </div>

    {#if tracing === "on"}
      <div class="field">
        <label for="trace-depth">How much to keep</label>
        <div class="help">
          Statements are diagnostics: the SQL, how long it waited, where it ran and what it returned a count of.
          Result data is a sample of your production rows, kept in a second file with a retention of its own — useful
          when you are chasing a wrong answer rather than a slow one, and worth choosing deliberately.
        </div>
        <select id="trace-depth" bind:value={traceDepth}>
          <option value="statements">Queries only — the SQL, timings, target and outcome</option>
          <option value="full">Queries and their results — plus a sample of the rows returned</option>
        </select>
      </div>

      {#if traceDepth === "full"}
        <div class="help notice">
          Row values are captured verbatim, up to a per-query cap the <strong>Query trace</strong> screen states
          exactly. Bind parameters are never recorded, but anything a query <em>returns</em> is — including personal
          data and anything a client selected out of a credentials table. You can change this later on the
          <strong>Databases</strong> page without recreating the pool.
        </div>
      {/if}
    {/if}
      </div>
    </section>

    <div class="connection-actions">
      <button class="action" type="button" onclick={backToCatalog}>Back</button>
      <button class="action primary" type="submit" disabled={submitting}>
        {submitting ? "Creating…" : "Create connection"}
      </button>
    </div>
  </form>
{/if}
