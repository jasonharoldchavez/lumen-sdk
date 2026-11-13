import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");

test("inline application script parses", () => {
  const match = html.match(/<script>([\\s\\S]*?)<\\/script>/i);
  assert.ok(match, "inline application script exists");
  assert.doesNotThrow(() => new vm.Script(match[1]));
});

test("page has a restrictive no-upload content security policy", () => {
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /default-src 'none'/);
  assert.doesNotMatch(html, /<script[^>]+src=/i);
  assert.doesNotMatch(html, /<link[^>]+href=/i);
});

test("file proof uses browser SHA-256 and documents scope", () => {
  assert.match(html, /crypto\\.subtle\\.digest\\("SHA-256"/);
  assert.match(html, /100 \\* 1024 \\* 1024/);
  assert.match(html, /does not prove who created the file/i);
  assert.match(html, /does not establish who created a file/i);
});
