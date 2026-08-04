<script lang="ts">
  import type { Warning } from "../lib/types";

  let { warnings }: { warnings: Warning[] } = $props();

  /**
   * The session-mode warning is the important one. Setting `max_size = 3` on a
   * session-mode pool does not save backend connections; it queues clients
   * until they time out. This is the single most common way operators
   * misconfigure a pooler, and no other tool says so out loud.
   */
  function explain(w: Warning): { title: string; detail: string } {
    switch (w.kind) {
      case "session_mode_queues":
        return {
          title: `${w.pool}: session mode cannot reduce backend connections`,
          detail:
            `Up to ${w.max_client_connections} clients share ${w.max_size} backends, but in session mode a ` +
            `client holds its backend until it disconnects. ${Math.max(0, w.max_client_connections - w.max_size)} ` +
            `clients will queue and then fail with a timeout. Switch this pool to transaction mode, or raise max_size.`,
        };
      case "backends_exceed_clients":
        return {
          title: `${w.pool}: more backends than clients can use`,
          detail: `max_size is ${w.max_size} but at most ${w.max_client_connections} clients are accepted. The extra backend slots will never be used.`,
        };
      case "pool_without_users":
        return {
          title: `${w.pool}: no user can reach this pool`,
          detail: "Grant a user access to it, otherwise nothing will ever connect.",
        };
      case "split_without_replicas":
        return {
          title: `${w.pool}: read/write split has no replica`,
          detail: "Add at least one replica target or turn read/write split off. All traffic currently goes to the primary.",
        };
      case "no_sticky_window":
        return {
          title: `${w.pool}: reads may be stale immediately after a write`,
          detail: "Set a sticky-after-write window comfortably above your replication lag.",
        };
      case "users_without_backend_role":
        return {
          title: `${w.pool}: ${w.users.join(", ")} cannot connect`,
          detail:
            `This pool authenticates every client as itself and has no service account to fall back on, but ` +
            `${w.users.join(", ")} ${w.users.length === 1 ? "is" : "are"} not marked as having a database role of ` +
            `their own. Tick "Connect to the database as this user" on the Users page, or give the pool a backend user.`,
        };
      case "password_without_tls":
        return {
          title: `${w.pool}: database passwords cross the network in the clear`,
          detail:
            `This pool authenticates every client as itself, so the password it asks for is that client's ` +
            `PostgreSQL password. allow_password_without_tls is on, so it is asked for even when the client ` +
            `did not negotiate TLS. Anyone who can read that traffic can connect to the database directly, ` +
            `without going through havuz at all. Configure server.tls.cert and server.tls.key and turn this off.`,
        };
      case "passthrough_pool":
        return {
          title: `${w.pool}: unknown clients are checked by the database, not by havuz`,
          detail:
            `This pool admits clients it has no user record for by opening a database connection with the ` +
            `credentials they supplied. That is the point of the mode — nothing here stores a backend password — ` +
            `but it also means a first attempt from anyone who can reach this pool's port reaches ` +
            `PostgreSQL's authentication. Once an identity has been accepted its verifier is held in memory and ` +
            `later attempts are refused by havuz. Users you have configured are unaffected: their password, pool ` +
            `grants, read-only and disabled flags all still apply first.`,
        };
      case "read_only_not_enforced":
        return {
          title: `${w.pool}: read-only is not enforced in session mode`,
          detail:
            `${w.users.join(", ")} ${w.users.length === 1 ? "is" : "are"} marked read-only, but this pool runs in ` +
            `session mode, where havuz forwards bytes without reading statements. The setting is applied as a ` +
            `default and the client can turn it off again. Move the pool to transaction mode, or enforce it with ` +
            `database privileges instead.`,
        };
    }
  }
</script>

{#each warnings as w (w.kind + w.pool)}
  {@const info = explain(w)}
  <div class="warning">
    <strong>{info.title}</strong>
    <div>{info.detail}</div>
  </div>
{/each}
