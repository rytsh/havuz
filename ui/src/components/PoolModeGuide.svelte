<script lang="ts">
  import type { PoolMode } from "../lib/types";

  let { mode }: { mode: PoolMode } = $props();

  const modes: { id: PoolMode; title: string; badge: string; detail: string; use: string }[] = [
    {
      id: "session",
      title: "Session",
      badge: "Maximum compatibility",
      detail: "One client reserves one backend until it disconnects, even while idle. There is no multiplexing.",
      use: "Use for session state, LISTEN, temp tables, or clients that cannot tolerate transaction pooling.",
    },
    {
      id: "transaction",
      title: "Transaction",
      badge: "Recommended",
      detail: "A backend is held only while a transaction is open. Idle clients do not consume backend slots.",
      use: "Best default for APIs, workers, ORMs, and other ordinary application traffic.",
    },
    {
      id: "statement",
      title: "Statement",
      badge: "Aggressive",
      detail: "Targets statement-level sharing, but still holds one backend when an explicit transaction is open.",
      use: "Use only for autocommit workloads after testing driver behavior and pin analysis.",
    },
  ];
</script>

<div class="mode-guide">
  {#each modes as item (item.id)}
    <article class:active={mode === item.id}>
      <div class="mode-guide-head"><strong>{item.title}</strong><span>{item.badge}</span></div>
      <p>{item.detail}</p>
      <small>{item.use}</small>
    </article>
  {/each}
</div>
