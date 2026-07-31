<script lang="ts">
  import { link } from "svelte-spa-router";
</script>

<div class="trace-empty py-16">
  <h1>Page not found</h1>
  <p class="subtitle mx-auto">The requested admin page does not exist.</p>
  <a class="action primary" href="/" use:link>Return to dashboard</a>
</div>
