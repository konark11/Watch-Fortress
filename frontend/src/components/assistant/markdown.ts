export type BlockToken =
  | { type: "code"; language: string; content: string }
  | { type: "heading"; level: 1 | 2 | 3 | 4 | 5 | 6; text: string }
  | { type: "table"; headers: string[]; rows: string[][] }
  | { type: "blockquote"; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "paragraph"; text: string };

export type InlineToken =
  | { type: "text"; text: string }
  | { type: "bold"; text: string }
  | { type: "italic"; text: string }
  | { type: "code"; text: string }
  | { type: "cve"; id: string }
  | { type: "link"; text: string; href: string; isSafe: boolean };

/**
 * Validates whether a URL is safe for anchor hrefs.
 * Blocks dangerous schemes like javascript:, data:, vbscript:.
 */
export function isSafeUrl(rawUrl: string): boolean {
  if (!rawUrl) return false;
  const trimmed = rawUrl.trim();
  // Allow relative URLs starting with / (excluding // which are protocol-relative)
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) return true;
  // Allow safe protocols
  try {
    const parsed = new URL(trimmed);
    return ["http:", "https:", "mailto:"].includes(parsed.protocol.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * Splits raw markdown text into high-level structural block tokens.
 */
export function parseMarkdownBlocks(text: string): BlockToken[] {
  if (!text) return [];
  const lines = text.split(/\r?\n/);
  const blocks: BlockToken[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // 1. Fenced code block: ```lang ... ```
    const codeMatch = line.match(/^```(\w*)/);
    if (codeMatch) {
      const language = codeMatch[1]?.trim() || "text";
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++; // skip closing ```
      blocks.push({
        type: "code",
        language,
        content: codeLines.join("\n"),
      });
      continue;
    }

    // 2. Blank line: skip
    if (!line.trim()) {
      i++;
      continue;
    }

    // 3. Headings: #, ##, ###
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      blocks.push({
        type: "heading",
        level: headingMatch[1].length as 1 | 2 | 3 | 4 | 5 | 6,
        text: headingMatch[2].trim(),
      });
      i++;
      continue;
    }

    // 4. Blockquotes: > quote
    if (line.startsWith(">")) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].startsWith(">")) {
        quoteLines.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      blocks.push({
        type: "blockquote",
        text: quoteLines.join("\n"),
      });
      continue;
    }

    // 5. Tables: | col | col | followed by | --- | --- |
    if (
      line.trim().startsWith("|") &&
      line.trim().endsWith("|") &&
      i + 1 < lines.length &&
      /^\|[\s\-:|]+\|$/.test(lines[i + 1].trim())
    ) {
      const parseCells = (row: string) =>
        row
          .trim()
          .slice(1, -1)
          .split("|")
          .map((c) => c.trim());

      const headers = parseCells(line);
      i += 2; // skip header and delimiter lines
      const rows: string[][] = [];

      while (
        i < lines.length &&
        lines[i].trim().startsWith("|") &&
        lines[i].trim().endsWith("|")
      ) {
        rows.push(parseCells(lines[i]));
        i++;
      }

      blocks.push({
        type: "table",
        headers,
        rows,
      });
      continue;
    }

    // 6. Lists: unordered (- or *) or ordered (1.)
    const isUnordered = /^[-*]\s+(.*)$/.test(line);
    const isOrdered = /^\d+\.\s+(.*)$/.test(line);
    if (isUnordered || isOrdered) {
      const items: string[] = [];
      const ordered = isOrdered;

      while (i < lines.length) {
        const cur = lines[i];
        const match = ordered
          ? cur.match(/^\d+\.\s+(.*)$/)
          : cur.match(/^[-*]\s+(.*)$/);
        if (match) {
          items.push(match[1]);
          i++;
        } else if (
          cur.startsWith("  ") &&
          items.length > 0 &&
          cur.trim().length > 0
        ) {
          // continuation line of previous list item
          items[items.length - 1] += " " + cur.trim();
          i++;
        } else {
          break;
        }
      }

      blocks.push({
        type: "list",
        ordered,
        items,
      });
      continue;
    }

    // 7. Regular paragraph: gather consecutive non-empty lines
    const paragraphLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim().length > 0 &&
      !lines[i].startsWith("```") &&
      !lines[i].startsWith("#") &&
      !lines[i].startsWith(">") &&
      !/^[-*]\s+/.test(lines[i]) &&
      !/^\d+\.\s+/.test(lines[i]) &&
      !(lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|"))
    ) {
      paragraphLines.push(lines[i]);
      i++;
    }

    if (paragraphLines.length > 0) {
      blocks.push({
        type: "paragraph",
        text: paragraphLines.join("\n"),
      });
    }
  }

  return blocks;
}

/**
 * Parses inline formatting: bold, italic, code, CVE badges, links.
 */
export function parseInline(text: string): InlineToken[] {
  if (!text) return [];

  // Match pattern for inline syntax:
  // 1: code `...`
  // 2: bold **...**
  // 3: italic *...*
  // 4: links [label](url)
  // 5: CVE-YYYY-NNNN+
  const inlineRegex =
    /(`([^`]+)`)|\*\*([^*]+)\*\*|(?:\*([^*]+)\*)|\[([^\]]+)\]\(([^)]+)\)|(CVE-\d{4}-\d{4,7})/gi;

  const tokens: InlineToken[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = inlineRegex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({
        type: "text",
        text: text.slice(lastIndex, match.index),
      });
    }

    if (match[2] !== undefined) {
      // Inline code: `code`
      tokens.push({ type: "code", text: match[2] });
    } else if (match[3] !== undefined) {
      // Bold: **text**
      tokens.push({ type: "bold", text: match[3] });
    } else if (match[4] !== undefined) {
      // Italic: *text*
      tokens.push({ type: "italic", text: match[4] });
    } else if (match[5] !== undefined && match[6] !== undefined) {
      // Link: [label](url)
      const linkText = match[5];
      const href = match[6];
      tokens.push({
        type: "link",
        text: linkText,
        href,
        isSafe: isSafeUrl(href),
      });
    } else if (match[7] !== undefined) {
      // CVE identifier
      tokens.push({ type: "cve", id: match[7].toUpperCase() });
    }

    lastIndex = inlineRegex.lastIndex;
  }

  if (lastIndex < text.length) {
    tokens.push({
      type: "text",
      text: text.slice(lastIndex),
    });
  }

  return tokens;
}
