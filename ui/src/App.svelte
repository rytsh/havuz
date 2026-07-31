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
    { path: "/", label: "Dashboard", marker: "01" },
    { path: "/databases", label: "Databases", marker: "02" },
    { path: "/databases/new", label: "Add database", marker: "+" },
    { path: "/targets", label: "Targets", marker: "03" },
    { path: "/pins", label: "Pin analysis", marker: "04" },
    { path: "/trace", activePath: /^\/trace(?:\/.*)?$/, label: "Query trace", marker: "05" },
    { path: "/users", label: "Users", marker: "06" },
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
      <div>
        havuz
        <small>PostgreSQL traffic control</small>
      </div>
    </div>
    <nav class="nav">
      {#each tabs as t (t.path)}
        <a href={t.path} use:link use:active={{ path: t.activePath ?? t.path, className: "active" }}>
          <span>{t.label}</span>
          <span class="nav-marker">{t.marker}</span>
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
