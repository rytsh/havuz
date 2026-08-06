<script lang="ts">
  import { getToken, setToken, setUnauthorizedHandler } from "../lib/api";

  /**
   * Asks for the admin token the first time the API says it wants one.
   *
   * Only listeners that are not on loopback have a token at all, so on a local
   * havuz this component never appears. On a remote one — a container, mostly —
   * it is the only way in: the token is deliberately not in the config file the
   * dashboard can read, and there is no login endpoint to redirect to.
   */
  let asking = $state(false);
  let refused = $state(false);
  let token = $state("");

  setUnauthorizedHandler(() => {
    if (asking) return;
    // A token that was already here and still got a 401 is the wrong token,
    // which is worth saying rather than showing the same empty box again.
    refused = getToken() !== null;
    asking = true;
  });

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const value = token.trim();
    if (!value) return;
    setToken(value);
    // Every view fetched its data before there was a token and got nothing.
    // Reloading re-runs all of them; replaying each one by hand would be the
    // same thing with more code to get wrong.
    location.reload();
  }
</script>

{#if asking}
  <div class="token-gate">
    <form class="token-card" onsubmit={submit}>
      <h1>Admin token</h1>
      {#if refused}
        <p class="help">The token stored for this tab was refused. Try another one.</p>
      {:else}
        <p class="help">
          This havuz serves its admin API on a routable address, so it authenticates. The token is the
          value of the environment variable named by <code>admin.auth.token_env</code> — in the container
          image, <code>HAVUZ_ADMIN_TOKEN</code>, which the entrypoint prints on startup when it had to
          generate one.
        </p>
      {/if}
      <div class="field">
        <label for="admin-token">Token</label>
        <input id="admin-token" type="password" autocomplete="off" spellcheck="false" bind:value={token} />
      </div>
      <button class="action primary" type="submit" disabled={!token.trim()}>Unlock</button>
      <p class="help mt-3">
        Kept in this tab's session storage. Closing the tab forgets it.
      </p>
    </form>
  </div>
{/if}
