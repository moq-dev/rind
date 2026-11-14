import { expect, test } from "bun:test";
import type { Token } from "marked";
import { hrefs, inline, lex } from "./markdown";

// Each link's destination and title, nested ones included.
function links(tokens: Token[]): [string, string | null | undefined][] {
	return tokens.flatMap((t) => [
		...(t.type === "link" ? [[t.href, t.title] as [string, string | null | undefined]] : []),
		...("tokens" in t && t.tokens ? links(t.tokens) : []),
	]);
}

// A destination with any character survives being written back as Markdown.
test.each([
	"[a](<https://example.com/a)b>)",
	"[a](https://en.wikipedia.org/wiki/X_(y))",
	"[a](<https://example.com/a b>)",
	"[a](<https://example.com/\\<x\\>>)",
	"[a](https://example.com/a\\b)",
	'[a](https://example.com "say \\"hi\\" \\\\ there")',
	"[a][r]\n\n[r]: <https://example.com/(r> 'ref'",
])("%s", (source) => {
	const before = lex(source);
	const paragraph = before.find((t) => t.type === "paragraph");
	const written = inline(paragraph && "tokens" in paragraph ? (paragraph.tokens ?? []) : []);
	expect(links(lex(written))).toEqual(links(before));
	expect(links(before).length).toBe(1);
});

// Links in table cells, header and body, are found like any other.
test("hrefs reads table cells", () => {
	expect(hrefs(lex("| [Head](/head) |\n| --- |\n| [Missing](/missing) |"))).toEqual(["/head", "/missing"]);
});
