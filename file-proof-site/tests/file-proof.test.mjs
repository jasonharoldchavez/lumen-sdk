import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");

test("inline application script parses", () => {
  const start = html.indexOf("<script>");
  const end = html.indexOf("</script>", start + 8);
  assert.ok(start >= 0 && end > start, "inline application script exists");
  const source = html.slice(start + 8, end);
  assert.doesNotThrow(() => new vm.Script(source));
});

test("page has a restrictive no-upload content security policy", () => {
  assert.ok(html.includes("connect-src 'none'"));
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(!html.includes("<script src="));
  assert.ok(!html.includes("<link href="));
});

test("file proof uses browser SHA-256 and documents scope", () => {
  assert.ok(html.includes('crypto.subtle.digest("SHA-256"'));
  assert.ok(html.includes("100 * 1024 * 1024"));
  assert.ok(html.toLowerCase().includes("does not establish who created a file"));
});
