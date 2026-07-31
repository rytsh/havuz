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
