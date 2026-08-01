<script lang="ts">
  import { api } from "../lib/api";
  import type { Pool, User } from "../lib/types";

  let users = $state<User[]>([]);
  let pools = $state<Pool[]>([]);
  let error = $state<string | null>(null);
  let creating = $state(false);

  let name = $state("");
  let password = $state("");
  let granted = $state<string[]>([]);
  let readOnly = $state(false);
  let created = $state<{ name: string; password: string } | null>(null);

  /** The user being edited, and the draft of the changes. */
  let editing = $state<string | null>(null);
  let draft = $state<{
    pools: string[];
    readOnly: boolean;
    ownBackendRole: boolean;
    maxConnections: number;
    description: string;
    password: string;
  }>({
    pools: [],
    readOnly: false,
    ownBackendRole: false,
    maxConnections: 0,
    description: "",
    password: "",
  });
  let busy = $state<string | null>(null);
  let notice = $state<string | null>(null);

  async function refresh() {
    try {
      [users, pools] = await Promise.all([api.users(), api.pools().then((r) => r.pools)]);
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  /** Run a mutation for one user, keeping its row disabled meanwhile. */
  async function act(user: string, run: () => Promise<string | null>) {
    busy = user;
    error = null;
    notice = null;
    try {
      notice = await run();
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = null;
    }
  }

  function startEdit(user: User) {
    editing = user.name;
    draft = {
      pools: [...user.pools],
      readOnly: user.read_only,
      ownBackendRole: user.own_backend_role,
      maxConnections: user.max_client_connections,
      description: user.description ?? "",
      password: "",
    };
  }

  async function saveEdit(user: User) {
    // Only the password is optional-by-omission; everything else is sent as
    // shown, because the form displays the user's current values.
    const body: Record<string, unknown> = {
      pools: draft.pools,
      read_only: draft.readOnly,
      own_backend_role: draft.ownBackendRole,
      max_client_connections: draft.maxConnections,
      description: draft.description.trim() === "" ? null : draft.description.trim(),
    };
    if (draft.password !== "") body.password = draft.password;

    await act(user.name, async () => {
      await api.updateUser(user.name, body);
      editing = null;
      return `Saved ${user.name}.`;
    });
  }

  async function setDisabled(user: User, disabled: boolean) {
    // Disabling only refuses the next handshake, so offer to end the sessions
    // that are already running rather than leaving the operator to discover
    // that access was not actually revoked.
    let kick = false;
    if (disabled && user.live_sessions > 0) {
      kick = confirm(
        `${user.name} has ${user.live_sessions} live session(s).\n\n` +
          `Disabling only blocks new connections. Disconnect the existing ones too?\n\n` +
          `OK = disable and disconnect, Cancel = disable only.`,
      );
    }
    await act(user.name, async () => {
      const result = await api.updateUser(user.name, { disabled, kick });
      if (!disabled) return `Enabled ${user.name}.`;
      return kick ? `Disabled ${user.name} and ended ${result.kicked} session(s).` : `Disabled ${user.name}.`;
    });
  }

  async function kick(user: User) {
    if (!confirm(`Disconnect ${user.live_sessions} session(s) belonging to "${user.name}"?`)) return;
    await act(user.name, async () => {
      const result = await api.kickUser(user.name);
      return `Disconnected ${result.kicked} session(s).`;
    });
  }

  function toggleDraftPool(pool: string) {
    draft.pools = draft.pools.includes(pool) ? draft.pools.filter((p) => p !== pool) : [...draft.pools, pool];
  }

  function generate() {
    // Generated in the browser so a weak operator-chosen password is never the
    // default path. 160 bits of entropy, base64url.
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    password = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function submit(event: Event) {
    event.preventDefault();
    creating = true;
    error = null;
    try {
      await api.createUser({ name, password, pools: granted, read_only: readOnly });
      // Shown exactly once: havuz stores a SCRAM verifier, so it genuinely
      // cannot show this again later.
      created = { name, password };
      name = "";
      password = "";
      granted = [];
      readOnly = false;
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      creating = false;
    }
  }

  async function remove(user: string) {
    if (!confirm(`Delete user "${user}"?`)) return;
    try {
      await api.deleteUser(user);
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  function toggle(pool: string) {
    granted = granted.includes(pool) ? granted.filter((p) => p !== pool) : [...granted, pool];
  }

  $effect(() => {
    refresh();
    // Live session counts go stale fast, and they are the number an operator
    // reads before deciding whether disabling someone is safe.
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  });
</script>

<h1>Users</h1>
<p class="subtitle">
  Clients authenticate against havuz with these credentials, not against the database. havuz reaches the database with
  the pool's own service account.
</p>

{#if error}
  <div class="error">{error}</div>
{/if}

{#if notice}
  <div class="warning">{notice}<button class="action mt-2" onclick={() => (notice = null)}>Dismiss</button></div>
{/if}

{#if created}
  <div class="warning">
    <strong>Save this password now — it cannot be shown again.</strong>
    <div class="mt-1.5 overflow-x-auto">
      <code>postgresql://{created.name}:{created.password}@&lt;havuz-host&gt;:5432/&lt;pool&gt;</code>
    </div>
    <button class="action mt-2" onclick={() => (created = null)}>Dismiss</button>
  </div>
{/if}

{#if users.length > 0}
  <div class="table-scroll">
  <table>
    <thead>
      <tr>
        <th>User</th>
        <th>Pools</th>
        <th>Access</th>
        <th>Limit</th>
        <th>Live</th>
        <th>Status</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each users as user (user.name)}
        <tr class:dimmed={user.disabled}>
          <td>
            <strong>{user.name}</strong>
            {#if user.description}<div class="muted text-xs">{user.description}</div>{/if}
          </td>
          <td class="muted">{user.pools.join(", ")}</td>
          <td>
            {#if user.read_only}
              <span class="badge">read only</span>
            {:else}
              <span class="badge ok">read / write</span>
            {/if}
          </td>
          <td class="muted">{user.max_client_connections === 0 ? "—" : user.max_client_connections}</td>
          <td>
            {#if user.live_sessions > 0}
              <strong>{user.live_sessions}</strong>
            {:else}
              <span class="muted">0</span>
            {/if}
          </td>
          <td>
            {#if user.disabled}
              <span class="badge warn">disabled</span>
            {:else}
              <span class="badge ok">active</span>
            {/if}
          </td>
          <td>
            <div class="row justify-end">
              <button class="action" disabled={busy === user.name} onclick={() => startEdit(user)}>Edit</button>
              {#if user.disabled}
                <button class="action" disabled={busy === user.name} onclick={() => setDisabled(user, false)}>
                  Enable
                </button>
              {:else}
                <button class="action" disabled={busy === user.name} onclick={() => setDisabled(user, true)}>
                  Disable
                </button>
              {/if}
              <button
                class="action"
                disabled={busy === user.name || user.live_sessions === 0}
                title={user.live_sessions === 0 ? "Nothing connected" : "Disconnect this user's sessions"}
                onclick={() => kick(user)}
              >
                Disconnect
              </button>
              <button class="action danger" disabled={busy === user.name} onclick={() => remove(user.name)}>
                Delete
              </button>
            </div>
          </td>
        </tr>

        {#if editing === user.name}
          <tr>
            <td colspan="7">
              <form
                class="edit-panel"
                onsubmit={(event) => {
                  event.preventDefault();
                  saveEdit(user);
                }}
              >
                <div class="field">
                  <label for="edit-pools">Pool access</label>
                  <div id="edit-pools">
                    {#each pools as pool (pool.name)}
                      <label class="block font-normal">
                        <input
                          type="checkbox"
                          checked={draft.pools.includes(pool.name)}
                          onchange={() => toggleDraftPool(pool.name)}
                        />
                        {pool.name}
                      </label>
                    {/each}
                  </div>
                </div>

                <div class="field">
                  <label class="font-normal">
                    <input type="checkbox" bind:checked={draft.readOnly} />
                    Read only
                  </label>
                  <div class="help">
                    Enforced by PostgreSQL through <code>default_transaction_read_only</code>, so a write hidden inside
                    a function is caught too. Session-mode pools cannot enforce it — havuz does not inspect statements
                    there.
                  </div>
                </div>

                <div class="field">
                  <label class="font-normal">
                    <input type="checkbox" bind:checked={draft.ownBackendRole} />
                    Connect to the database as this user
                  </label>
                  <div class="help">
                    Only takes effect on pools configured for per-user authentication; elsewhere the pool's service
                    account is used either way. Requires a database role with this name and the same password, and gives
                    this user a set of backend connections of its own.
                  </div>
                </div>

                <div class="field">
                  <label for="edit-max">Maximum connections</label>
                  <div class="help">0 means no personal cap. Counted across every pool this user may reach.</div>
                  <input id="edit-max" type="number" min="0" bind:value={draft.maxConnections} />
                </div>

                <div class="field">
                  <label for="edit-description">Description</label>
                  <input id="edit-description" bind:value={draft.description} placeholder="Orders API service account" />
                </div>

                <div class="field">
                  <label for="edit-password">New password</label>
                  <div class="help">Leave blank to keep the current one. Existing sessions are not disconnected.</div>
                  <input id="edit-password" type="text" bind:value={draft.password} placeholder="unchanged" />
                </div>

                <div class="row">
                  <button class="action primary" type="submit" disabled={busy === user.name || draft.pools.length === 0}>
                    {busy === user.name ? "Saving…" : "Save"}
                  </button>
                  <button class="action" type="button" onclick={() => (editing = null)}>Cancel</button>
                </div>
              </form>
            </td>
          </tr>
        {/if}
      {/each}
    </tbody>
  </table>
  </div>
{:else}
  <p class="muted">No users yet.</p>
{/if}

<h2>Create user</h2>

{#if pools.length === 0}
  <p class="muted">Add a database first — a user with no pool grants could never connect.</p>
{:else}
  <form onsubmit={submit}>
    <div class="field">
      <label for="user-name">Name</label>
      <input id="user-name" bind:value={name} required placeholder="svc_orders" />
    </div>

    <div class="field">
      <label for="user-password">Password</label>
      <div class="help">Stored as a SCRAM verifier. havuz never keeps the password itself.</div>
      <div class="row">
        <input id="user-password" type="text" bind:value={password} required />
        <button class="action" type="button" onclick={generate}>Generate</button>
      </div>
    </div>

    <div class="field">
      <label for="grants">Pool access</label>
      <div id="grants">
        {#each pools as pool (pool.name)}
          <label class="block font-normal">
            <input type="checkbox" checked={granted.includes(pool.name)} onchange={() => toggle(pool.name)} />
            {pool.name}
          </label>
        {/each}
      </div>
    </div>

    <div class="field">
      <label class="font-normal">
        <input type="checkbox" bind:checked={readOnly} />
        Read only
      </label>
    </div>

    <button class="action primary" type="submit" disabled={creating || granted.length === 0}>
      {creating ? "Creating…" : "Create user"}
    </button>
  </form>
{/if}
