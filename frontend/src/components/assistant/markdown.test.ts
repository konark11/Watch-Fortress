import { describe, it } from "node:test";
import assert from "node:assert";
import { isSafeUrl, parseMarkdownBlocks, parseInline } from "./markdown.ts";

describe("Markdown Parser & Sanitizer", () => {
  it("validates safe and unsafe URLs strictly", () => {
    // Safe URLs
    assert.strictEqual(isSafeUrl("https://nvd.nist.gov/vuln/detail/CVE-2023-48795"), true);
    assert.strictEqual(isSafeUrl("http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48795"), true);
    assert.strictEqual(isSafeUrl("mailto:security@example.com"), true);
    assert.strictEqual(isSafeUrl("/vulnerabilities"), true);

    // Unsafe / malicious schemes
    assert.strictEqual(isSafeUrl("javascript:alert(1)"), false);
    assert.strictEqual(isSafeUrl("data:text/html,<script>alert(1)</script>"), false);
    assert.strictEqual(isSafeUrl("vbscript:MsgBox(1)"), false);
    assert.strictEqual(isSafeUrl("//evil.com/phish"), false); // protocol-relative blocked
    assert.strictEqual(isSafeUrl(""), false);
  });

  it("parses code blocks with language", () => {
    const input = "```bash\nsudo systemctl restart sshd\n```";
    const blocks = parseMarkdownBlocks(input);
    assert.strictEqual(blocks.length, 1);
    assert.strictEqual(blocks[0].type, "code");
    if (blocks[0].type === "code") {
      assert.strictEqual(blocks[0].language, "bash");
      assert.strictEqual(blocks[0].content, "sudo systemctl restart sshd");
    }
  });

  it("parses headings correctly", () => {
    const input = "# Title\n\n## Subtitle\n\n### Details";
    const blocks = parseMarkdownBlocks(input);
    assert.strictEqual(blocks.length, 3);
    assert.strictEqual(blocks[0].type, "heading");
    assert.strictEqual(blocks[1].type, "heading");
    assert.strictEqual(blocks[2].type, "heading");
    if (blocks[0].type === "heading" && blocks[1].type === "heading" && blocks[2].type === "heading") {
      assert.strictEqual(blocks[0].level, 1);
      assert.strictEqual(blocks[0].text, "Title");
      assert.strictEqual(blocks[1].level, 2);
      assert.strictEqual(blocks[1].text, "Subtitle");
      assert.strictEqual(blocks[2].level, 3);
      assert.strictEqual(blocks[2].text, "Details");
    }
  });

  it("parses tables into structured rows and cells", () => {
    const tableText = [
      "| CVE | Severity | Asset |",
      "| --- | --- | --- |",
      "| CVE-2023-48795 | High | 10.0.0.1 |",
      "| CVE-2024-6387 | Critical | 10.0.0.2 |",
    ].join("\n");

    const blocks = parseMarkdownBlocks(tableText);
    assert.strictEqual(blocks.length, 1);
    assert.strictEqual(blocks[0].type, "table");
    if (blocks[0].type === "table") {
      assert.deepStrictEqual(blocks[0].headers, ["CVE", "Severity", "Asset"]);
      assert.strictEqual(blocks[0].rows.length, 2);
      assert.deepStrictEqual(blocks[0].rows[0], ["CVE-2023-48795", "High", "10.0.0.1"]);
      assert.deepStrictEqual(blocks[0].rows[1], ["CVE-2024-6387", "Critical", "10.0.0.2"]);
    }
  });

  it("parses lists (ordered and unordered)", () => {
    const input = "- OpenSSH update\n- Disable vulnerable ciphers\n- Verify audit log";
    const blocks = parseMarkdownBlocks(input);
    assert.strictEqual(blocks.length, 1);
    assert.strictEqual(blocks[0].type, "list");
    if (blocks[0].type === "list") {
      assert.strictEqual(blocks[0].ordered, false);
      assert.strictEqual(blocks[0].items.length, 3);
      assert.strictEqual(blocks[0].items[0], "OpenSSH update");
    }
  });

  it("parses inline formatting including bold, inline code, CVEs, and links", () => {
    const input = "Patch `sshd_config` for **CVE-2023-48795** per [NVD Guide](https://nvd.nist.gov).";
    const tokens = parseInline(input);

    const types = tokens.map((t) => t.type);
    assert.ok(types.includes("code"));
    assert.ok(types.includes("bold"));
    assert.ok(types.includes("link"));

    const linkToken = tokens.find((t) => t.type === "link");
    assert.ok(linkToken);
    if (linkToken && linkToken.type === "link") {
      assert.strictEqual(linkToken.text, "NVD Guide");
      assert.strictEqual(linkToken.href, "https://nvd.nist.gov");
      assert.strictEqual(linkToken.isSafe, true);
    }
  });

  it("disarms malicious javascript: links in inline text", () => {
    const input = "Click [here](javascript:alert('pwned')) to remediate.";
    const tokens = parseInline(input);
    const linkToken = tokens.find((t) => t.type === "link");
    assert.ok(linkToken);
    if (linkToken && linkToken.type === "link") {
      assert.strictEqual(linkToken.isSafe, false);
    }
  });
});
