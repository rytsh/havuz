<script lang="ts">
  import type { DatabaseIcon } from "../lib/icons";

  let { icon, large = false }: { icon: DatabaseIcon; large?: boolean } = $props();
</script>

<span
  class="database-mark"
  class:large
  style={`--brand:#${icon.hex}`}
  role="img"
  aria-label={icon.title}
>
  <svg viewBox={icon.viewBox ?? "0 0 24 24"} aria-hidden="true">
    <path d={icon.path}></path>
  </svg>
</span>
