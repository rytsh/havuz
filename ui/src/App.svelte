<script lang="ts">
  import Router, { link } from "svelte-spa-router";
  import active from "svelte-spa-router/active";
  import Dashboard from "./routes/Dashboard.svelte";
  import Pools from "./routes/Pools.svelte";
  import AddDatabase from "./routes/AddDatabase.svelte";
  import Pins from "./routes/Pins.svelte";
  import Targets from "./routes/Targets.svelte";
  import Trace from "./routes/Trace.svelte";
  import Users from "./routes/Users.svelte";
  import NotFound from "./routes/NotFound.svelte";

  const tabs = [
    { path: "/", label: "Dashboard" },
    { path: "/databases", label: "Databases" },
    { path: "/databases/new", label: "Add database" },
    { path: "/targets", label: "Targets" },
    { path: "/pins", label: "Pin analysis" },
    { path: "/trace", activePath: /^\/trace(?:\/.*)?$/, label: "Query trace" },
    { path: "/users", label: "Users" },
  ];

  const routes = {
    "/": Dashboard,
    "/databases": Pools,
    "/databases/new": AddDatabase,
    "/targets": Targets,
    "/pins": Pins,
    "/trace": Trace,
    "/trace/:id": Trace,
    "/users": Users,
    "*": NotFound,
  };
</script>

<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">H</div>
      <div>havuz</div>
    </div>
    <nav class="nav">
      {#each tabs as t (t.path)}
        <a href={t.path} use:link use:active={{ path: t.activePath ?? t.path, className: "active" }}>
          {t.label}
        </a>
      {/each}
    </nav>
    <div class="sidebar-foot">
      <span class="status-dot"></span>
      Admin console online
    </div>
  </aside>

  <main>
    <Router {routes} />
  </main>
</div>
