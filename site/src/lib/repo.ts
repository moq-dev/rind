import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

// Astro builds from site/, so the repository is its parent.
export const root = path.resolve(process.cwd(), "..");
if (!existsSync(path.join(root, "site", "package.json"))) {
	throw new Error(`run the site's build from site/, not ${process.cwd()}`);
}

// Where the repository's files are on GitHub, as the README links them.
export const repoUrl = "https://github.com/kixel-ai/rind";

// The files the build reads. sh/dispatch.sh's `site` scope must match each,
// which scripts/check.ts verifies, so the merge queue rebuilds the site when
// one changes.
export const sources = ["README.md", "admin/wordmark.svg", "admin/wordmark-light.svg"] as const;

// Read one of `sources`.
export function read(file: (typeof sources)[number]): string {
	return readFileSync(path.join(root, file), "utf8");
}
