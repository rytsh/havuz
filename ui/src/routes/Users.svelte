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

  async function refresh() {
    try {
      [users, pools] = await Promise.all([api.users(), api.pools().then((r) => r.pools)]);
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
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

{#if created}
  <div class="warning">
    <strong>Save this password now — it cannot be shown again.</strong>
    <div style="margin-top:6px">
      <code>postgresql://{created.name}:{created.password}@&lt;havuz-host&gt;:5432/&lt;pool&gt;</code>
    </div>
    <button class="action" style="margin-top:8px" onclick={() => (created = null)}>Dismiss</button>
  </div>
{/if}

{#if users.length > 0}
  <table>
    <thead>
      <tr>
        <th>User</th>
        <th>Pools</th>
        <th>Access</th>
        <th>Status</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each users as user (user.name)}
        <tr>
          <td><strong>{user.name}</strong></td>
          <td class="muted">{user.pools.join(", ")}</td>
          <td>
            {#if user.read_only}
              <span class="badge">read only</span>
            {:else}
              <span class="badge ok">read / write</span>
            {/if}
          </td>
          <td>
            {#if user.disabled}
              <span class="badge warn">disabled</span>
            {:else}
              <span class="badge ok">active</span>
            {/if}
          </td>
          <td><button class="action danger" onclick={() => remove(user.name)}>Delete</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
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
          <label style="display:block; font-weight:400">
            <input type="checkbox" checked={granted.includes(pool.name)} onchange={() => toggle(pool.name)} />
            {pool.name}
          </label>
        {/each}
      </div>
    </div>

    <div class="field">
      <label style="font-weight:400">
        <input type="checkbox" bind:checked={readOnly} />
        Read only
      </label>
    </div>

    <button class="action primary" type="submit" disabled={creating || granted.length === 0}>
      {creating ? "Creating…" : "Create user"}
    </button>
  </form>
{/if}
