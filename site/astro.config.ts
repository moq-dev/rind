import svelte from "@astrojs/svelte";
import { defineConfig } from "astro/config";

export default defineConfig({
	site: "https://rind.kixel.ai",
	output: "static",
	// `/` writes index.html, and a later `/from/ring` writes from/ring.html,
	// beside its twin from/ring.md.
	build: { format: "file" },
	integrations: [svelte()],
	devToolbar: { enabled: false },
});
