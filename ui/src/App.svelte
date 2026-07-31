<script lang="ts">
  import Dashboard from "./routes/Dashboard.svelte";
  import Pools from "./routes/Pools.svelte";
  import AddDatabase from "./routes/AddDatabase.svelte";
  import Pins from "./routes/Pins.svelte";
  import Targets from "./routes/Targets.svelte";
  import Users from "./routes/Users.svelte";

  type Tab = "dashboard" | "pools" | "add" | "targets" | "pins" | "users";

  let tab = $state<Tab>("dashboard");

  const tabs: { id: Tab; label: string }[] = [
    { id: "dashboard", label: "Dashboard" },
    { id: "pools", label: "Databases" },
    { id: "add", label: "Add database" },
    { id: "targets", label: "Targets" },
    { id: "pins", label: "Pin analysis" },
    { id: "users", label: "Users" },
  ];

  function goToPools() {
    tab = "pools";
  }
</script>

<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      havuz
      <small>connection pooler</small>
    </div>
    <nav class="nav">
      {#each tabs as t (t.id)}
        <button class:active={tab === t.id} onclick={() => (tab = t.id)}>{t.label}</button>
      {/each}
    </nav>
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
    {:else}
      <Users />
    {/if}
  </main>
</div>
