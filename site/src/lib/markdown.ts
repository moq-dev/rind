import { Lexer, Parser, type Token, type Tokens, type TokensList } from "marked";

// Parse a Markdown document, resolving its reference links.
export function lex(source: string): TokensList {
	return Lexer.lex(source, { gfm: true });
}

// The blocks under the heading named `title`, up to the next heading as deep or shallower.
export function section(tokens: Token[], title: string): Token[] {
	const start = tokens.findIndex((t) => t.type === "heading" && t.text === title);
	if (start < 0) throw new Error(`the README has no heading "${title}"`);
	const depth = (tokens[start] as Tokens.Heading).depth;
	const rest = tokens.slice(start + 1);
	const end = rest.findIndex((t) => t.type === "heading" && t.depth <= depth);
	return end < 0 ? rest : rest.slice(0, end);
}

export const html = (blocks: Token[]): string => Parser.parse(blocks);
export const inlineHtml = (inline: Token[]): string => Parser.parseInline(inline);

// Markdown for blocks, with reference links written inline, so a fragment
// reads on its own without the definitions at the end of its source.
export function markdown(blocks: Token[]): string {
	return blocks
		.map(block)
		.filter((b) => b !== "")
		.join("\n\n");
}

function block(token: Token): string {
	switch (token.type) {
		case "space":
			return "";
		case "paragraph":
			return inline(token.tokens ?? []);
		case "code":
			return token.raw.trimEnd();
		case "list":
			return (token as Tokens.List).items
				.map((item, i) => {
					const marker = (token as Tokens.List).ordered ? `${i + 1}.` : "-";
					const body = item.tokens.map((t) => (t.type === "text" ? inline(t.tokens ?? []) : block(t)));
					return `${marker} ${body.join("\n").replaceAll("\n", "\n  ")}`;
				})
				.join("\n");
		default:
			throw new Error(`no Markdown rendering for a ${token.type} block`);
	}
}

export function inline(tokens: Token[]): string {
	return tokens
		.map((t) => {
			switch (t.type) {
				case "text":
					return t.tokens ? inline(t.tokens) : t.raw;
				case "strong":
					return `**${inline(t.tokens ?? [])}**`;
				case "em":
					return `*${inline(t.tokens ?? [])}*`;
				case "link":
					return link(inline(t.tokens ?? []), t.href, t.title);
				case "codespan":
				case "escape":
				case "br":
					return t.raw;
				default:
					throw new Error(`no Markdown rendering for a ${t.type} span`);
			}
		})
		.join("");
}

// A Markdown link to `href`, which may hold any character: one with spaces,
// parentheses, or angle brackets goes between escaped angle brackets.
export function link(label: string, href: string, title?: string | null): string {
	const dest = /[\s()<>\\]/.test(href) ? `<${href.replace(/[<>\\]/g, "\\$&")}>` : href;
	return `[${label}](${dest}${title ? ` "${title.replace(/["\\]/g, "\\$&")}"` : ""})`;
}

// Every link target in some tokens, nested ones included.
export function hrefs(tokens: Token[]): string[] {
	const found: string[] = [];
	const walk = (list: Token[]) => {
		for (const t of list) {
			if (t.type === "link") found.push(t.href);
			if ("tokens" in t && t.tokens) walk(t.tokens);
			if (t.type === "list") for (const item of (t as Tokens.List).items) walk(item.tokens);
		}
	};
	walk(tokens);
	return found;
}
