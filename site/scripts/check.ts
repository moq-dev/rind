// Checks the built site in dist/, offline: every page has its Markdown twin, a
// line in llms.txt, and a sitemap entry; every link into the site or the
// repository resolves, anchors included; nothing loads from a third party; and
// the merge queue rebuilds the site when any repository file it reads or links
// changes.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { Lexer, type Token } from "marked";
import { hrefs, lex } from "../src/lib/markdown";
import { origin, pages, twinPath } from "../src/lib/pages";
import { repoUrl, root, sources } from "../src/lib/repo";

const dist = path.resolve("dist");
const errors = new Set<string>();
const fail = (msg: string) => void errors.add(msg);

function walk(dir: string): string[] {
	return readdirSync(dir).flatMap((name) => {
		const full = path.join(dir, name);
		return statSync(full).isDirectory() ? walk(full) : [full];
	});
}
const files = walk(dist).map((f) => `/${path.relative(dist, f).split(path.sep).join("/")}`);
const text = (file: string) => readFileSync(path.join(dist, file), "utf8");

// Pages, and what lists them.
const built = files
	.filter((f) => f.endsWith(".html"))
	.map((f) => (f === "/index.html" ? "/" : f.slice(0, -".html".length)));
const listed = new Set(pages.map((p) => p.path));
for (const page of built) if (!listed.has(page)) fail(`${page} is built but missing from src/lib/pages.ts`);
const llms = text("/llms.txt");
const sitemap = text("/sitemap.xml");
for (const page of pages) {
	if (!built.includes(page.path)) fail(`${page.path} is listed in src/lib/pages.ts but not built`);
	if (!files.includes(twinPath(page))) fail(`${page.path} has no Markdown twin at ${twinPath(page)}`);
	if (!llms.includes(`](${origin}${twinPath(page)})`)) fail(`llms.txt does not list ${twinPath(page)}`);
	if (!sitemap.includes(`<loc>${origin}${page.path}</loc>`)) fail(`sitemap.xml does not list ${page.path}`);
}

// The ids a built page's anchors can name.
const ids = (file: string) => new Set([...text(file).matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));

// GitHub's anchor for each heading of a repository Markdown file.
function anchors(file: string): Set<string> {
	const plain = (tokens: Token[]): string =>
		tokens
			.map((t) => ("tokens" in t && t.tokens ? plain(t.tokens) : "text" in t ? t.text : ""))
			.join("");
	// A repeated slug takes the next `-n` no earlier anchor holds, as github-slugger does,
	// so `Foo`, `Foo`, `Foo-1` are `foo`, `foo-1`, `foo-1-1`.
	const counts = new Map<string, number>();
	const out = new Set<string>();
	for (const t of Lexer.lex(readFileSync(path.join(root, file), "utf8"))) {
		if (t.type !== "heading") continue;
		const base = plain(t.tokens ?? [])
			.toLowerCase()
			.replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, "")
			.replaceAll(" ", "-");
		let slug = base;
		while (out.has(slug)) {
			const n = (counts.get(base) ?? 0) + 1;
			counts.set(base, n);
			slug = `${base}-${n}`;
		}
		out.add(slug);
	}
	return out;
}

// The merge queue's scope for the site, from sh/dispatch.sh.
const dispatch = readFileSync(path.join(root, "sh/dispatch.sh"), "utf8").match(/^\s*\[site\]='([^']+)'/m);
if (!dispatch) throw new Error("sh/dispatch.sh has no [site] scope");
const scope = new RegExp(dispatch[1]);
const repoFiles = new Set<string>(sources);

const blob = new RegExp(`^${repoUrl}/(?:blob|tree)/main/([^#?]+)`);
const raw = /^https:\/\/raw\.githubusercontent\.com\/kixel-ai\/rind\/main\/([^#?]+)/;

// Check one URL found in `from`, resolved against it as a browser would. A
// resource is fetched by the page itself, so it must be served from the site;
// a link the reader follows may go anywhere.
function check(from: string, url: string, resource: boolean) {
	let u: URL;
	let fragment: string;
	try {
		u = new URL(url, `${origin}${from}`);
		fragment = decodeURIComponent(u.hash.slice(1));
	} catch {
		return fail(`${from}: ${url} is not a valid URL`);
	}
	if (u.protocol === "data:") return;
	if (u.origin === origin) {
		const target = decodeURIComponent(u.pathname);
		const file = target.endsWith("/") ? `${target}index.html` : target;
		const found = [file, `${file}.html`].find((f) => files.includes(f));
		if (!found) return fail(`${from}: ${url} is not in the build`);
		if (fragment && !ids(found).has(fragment)) fail(`${from}: ${found} has no id "${fragment}"`);
		return;
	}
	if (u.protocol !== "https:") return fail(`${from}: ${url} is neither on this site nor https`);
	if (resource) return fail(`${from}: ${url} loads from a third party`);
	const located = `${u.origin}${u.pathname}`;
	const repoPath = located.match(blob)?.[1] ?? located.match(raw)?.[1];
	if (repoPath === undefined) return;
	const file = decodeURIComponent(repoPath).replace(/\/$/, "");
	repoFiles.add(file);
	if (!existsSync(path.join(root, file))) return fail(`${from}: ${url} names ${file}, which the repository lacks`);
	if (fragment && !(file.endsWith(".md") && anchors(file).has(fragment))) {
		fail(`${from}: ${url} names an anchor ${file} lacks`);
	}
}

// Stylesheets, inline or built, load through url() and a quoted @import.
function css(file: string, body: string) {
	for (const m of body.matchAll(/url\(\s*['"]?([^'")]+)/g)) check(file, m[1], true);
	for (const m of body.matchAll(/@import\s+['"]([^'"]+)/g)) check(file, m[1], true);
}

// Scripts, inline or built, load every module specifier, local ones included:
// `import "x"`, `import("x")`, and the `from "x"` of named imports and
// re-exports, minified or not.
function js(file: string, body: string) {
	for (const m of body.matchAll(/\b(?:import\s*\(?|from)\s*["']([^"']+)["']/g)) check(file, m[1], true);
}

for (const file of files) {
	if (file.endsWith(".html")) {
		const html = text(file);
		for (const m of html.matchAll(/<a\s[^>]*\bhref="([^"]*)"/g)) check(file, m[1], false);
		for (const m of html.matchAll(/<link\s[^>]*\bhref="([^"]*)"/g)) check(file, m[1], true);
		for (const m of html.matchAll(/\s(?:src|component-url|renderer-url)="([^"]*)"/g)) check(file, m[1], true);
		for (const m of html.matchAll(/\ssrcset="([^"]*)"/g)) {
			for (const candidate of m[1].split(",")) check(file, candidate.trim().split(/\s+/)[0], true);
		}
		css(file, html);
		for (const m of html.matchAll(/<script(?:\s+type="module")?\s*>([\s\S]*?)<\/script>/g)) js(file, m[1]);
	} else if (file.endsWith(".css")) {
		css(file, text(file));
	} else if (file.endsWith(".js")) {
		js(file, text(file));
	} else if (file.endsWith(".md") || file.endsWith(".txt")) {
		// Links, and URLs quoted as text, such as the prompt's.
		const body = text(file);
		for (const href of hrefs(lex(body))) check(file, href, false);
		for (const m of body.matchAll(/https?:\/\/[^\s)<>"'`\]]+/g)) check(file, m[0], false);
	}
}
for (const m of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) check("/sitemap.xml", m[1], false);

for (const file of repoFiles) {
	if (!scope.test(file)) fail(`sh/dispatch.sh's [site] scope misses ${file}, which the site reads or links`);
}

if (errors.size > 0) {
	for (const e of errors) console.error(`error: ${e}`);
	process.exit(1);
}
console.log(`site: ${built.length} page(s), ${files.length} files, and every link checked`);
