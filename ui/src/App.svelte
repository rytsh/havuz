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

  type Theme = "dark" | "light";

  let theme = $state<Theme>(document.documentElement.dataset.theme === "light" ? "light" : "dark");

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute(
      "content",
      theme === "light" ? "#F1FAEE" : "#252422",
    );
    try {
      localStorage.setItem("havuz-theme", theme);
    } catch {
      // The selected theme still applies when storage is unavailable.
    }
  }

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
      <div class="brand-identity">
        <div class="brand-mark" aria-hidden="true"><span></span></div>
        <div>havuz</div>
      </div>
      <button
        class="theme-toggle"
        type="button"
        onclick={toggleTheme}
        aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      >
        {#if theme === "dark"}
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="4"></circle>
            <path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41"></path>
          </svg>
          <span>Light</span>
        {:else}
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M20.6 15.2A8.5 8.5 0 0 1 8.8 3.4 8.5 8.5 0 1 0 20.6 15.2Z"></path>
          </svg>
          <span>Dark</span>
        {/if}
      </button>
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
