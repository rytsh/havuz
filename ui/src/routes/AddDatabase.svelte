<script lang="ts">
  import { push } from "svelte-spa-router";
  import { siCockroachlabs, siMysql, siOpenjdk, siPostgresql, siRedis } from "simple-icons";
  import type { SimpleIcon } from "simple-icons";
  import { api } from "../lib/api";
  import type { DriverProfile, Family, PoolMode, SchemaProperty } from "../lib/types";
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

  function iconFor(profile: DriverProfile): SimpleIcon {
    const known: Record<string, SimpleIcon> = {
      postgres: siPostgresql,
      cockroachdb: siCockroachlabs,
      redshift: siPostgresql,
      yugabytedb: siPostgresql,
      opengauss: siPostgresql,
      mysql: siMysql,
      redis: siRedis,
      generic: siOpenjdk,
    };
    return known[profile.id] ?? siOpenjdk;
  }

  function pick(family: Family, profile: DriverProfile) {
    if (!family.usable || profile.maturity === "planned") return;
    selected = family;
    profileId = profile.id;
    mode = family.default_pool_mode;
    // Seed defaults straight from the schema so the form starts valid.
    const seeded: Record<string, unknown> = {};
    for (const key of family.schema["x-havuz-order"] ?? []) {
      const prop = family.schema.properties[key];
      if (prop?.default !== undefined) seeded[key] = prop.default;
    }
    if (profile.default_port !== null) seeded.port = profile.default_port;
    settings = seeded;
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

  function isRequired(family: Family, key: string): boolean {
    return (family.schema.required ?? []).includes(key);
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

    // The connection fields live in `settings`; the pooler also needs a few of
    // them at the top level, so they are lifted rather than duplicated by hand.
    const host = String(settings.host ?? "");
    const port = Number(settings.port ?? selected.default_port);
    const password = settings.password ? String(settings.password) : undefined;

    const body = {
      name,
      family: selected.id,
      profile: profileId || undefined,
      mode,
      targets: [{ host, port }],
      database: String(settings.database ?? ""),
      backend_user: String(settings.username ?? ""),
      listen_port: listenPort || undefined,
      backend_password: password,
      limits: { max_size: maxSize, max_client_connections: maxClients },
      // The password is a credential, not configuration; it must not be echoed
      // back in the pool document.
      settings: Object.fromEntries(Object.entries(settings).filter(([k]) => k !== "password")),
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
      <div class="eyebrow">Connection catalog</div>
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
          {@const icon = iconFor(item.profile)}
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
          {@const icon = iconFor(selectedProfile)}
          <span class="database-mark" style={`--brand:#${icon.hex}`}>
            <svg viewBox="0 0 24 24" role="img" aria-label={icon.title}><path d={icon.path}></path></svg>
          </span>
        {/if}
        <div><div class="eyebrow">New connection</div><h1>{selectedProfile?.label ?? selected.label}</h1></div>
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
      <label for="listen-port">Dedicated listen port <span class="muted font-normal">(optional)</span></label>
      <div class="help">
        Opens a client-facing port only for this pool. Leave empty to use the shared listener and database-name routing.
      </div>
      <input id="listen-port" type="number" min="1" max="65535" bind:value={listenPort} placeholder="5544" />
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

    <div class="field">
      <label for="max-clients">Max client connections</label>
      <input id="max-clients" type="number" min="1" bind:value={maxClients} />
    </div>

    <div class="field">
      <label for="max-size">Max backend connections</label>
      <div class="help">The number that protects your database.</div>
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

    <div class="connection-actions">
      <button class="action" type="button" onclick={backToCatalog}>Back</button>
      <button class="action primary" type="submit" disabled={submitting}>
        {submitting ? "Creating…" : "Create connection"}
      </button>
    </div>
  </form>
{/if}
