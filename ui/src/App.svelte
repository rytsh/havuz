<script lang="ts">
  import Dashboard from "./routes/Dashboard.svelte";
  import Pools from "./routes/Pools.svelte";
  import AddDatabase from "./routes/AddDatabase.svelte";
  import Pins from "./routes/Pins.svelte";
  import Targets from "./routes/Targets.svelte";
  import Trace from "./routes/Trace.svelte";
  import Users from "./routes/Users.svelte";

  type Tab = "dashboard" | "pools" | "add" | "targets" | "pins" | "trace" | "users";

  let tab = $state<Tab>("dashboard");

  const tabs: { id: Tab; label: string; marker: string }[] = [
    { id: "dashboard", label: "Dashboard", marker: "01" },
    { id: "pools", label: "Databases", marker: "02" },
    { id: "add", label: "Add database", marker: "+" },
    { id: "targets", label: "Targets", marker: "03" },
    { id: "pins", label: "Pin analysis", marker: "04" },
    { id: "trace", label: "Query trace", marker: "05" },
    { id: "users", label: "Users", marker: "06" },
  ];

  function goToPools() {
    tab = "pools";
  }
</script>

<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">H</div>
      <div>
        havuz
        <small>PostgreSQL traffic control</small>
      </div>
    </div>
    <nav class="nav">
      {#each tabs as t (t.id)}
        <button class:active={tab === t.id} onclick={() => (tab = t.id)}>
          <span>{t.label}</span>
          <span class="nav-marker">{t.marker}</span>
        </button>
      {/each}
    </nav>
    <div class="sidebar-foot">
      <span class="status-dot"></span>
      Admin console online
    </div>
  </aside>

  <main>
    {#if tab === "dashboard"}
      <Dashboard />
    {:else if tab === "pools"}
      <Pools />
    {:else if tab === "add"}
      <AddDatabase onCreated={goToPools} />
    {:else if tab === "targets"}
      <Targets />
    {:else if tab === "pins"}
      <Pins />
    {:else if tab === "trace"}
      <Trace />
    {:else}
      <Users />
    {/if}
  </main>
</div>
