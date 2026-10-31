import test from "node:test";
import assert from "node:assert/strict";
import { contains, scan, redact, sanitize, sanitizeWithReport } from "../src/index.js";

const awsKey = "AKIA1234567890ABCDEF";

test("detects AWS access key without returning the secret in findings", () => {
  const result = scan(`key=${awsKey}`);
  assert.equal(result.found, true);
  assert.equal(result.findings[0].patternId, "aws.access-key");
  assert.equal("match" in result.findings[0], false);
  assert.equal(contains(`key=${awsKey}`), true);
});

test("redacts password assignments including the key", () => {
  assert.equal(redact('password="my-super-secret-password"'), "[REDACTED]");
  assert.equal(redact('пароль: superadmin'), "[REDACTED]");
  assert.equal(redact('passphrase: 123456'), "[REDACTED]");
  assert.equal(redact('pass: superadmin'), "[REDACTED]");
  assert.equal(redact('password: superadmin'), "[REDACTED]");
  assert.equal(redact("api_key=abcdefghijk"), "[REDACTED]");
  assert.equal(redact("pwd: Gy2Ps&F&y7"), "[REDACTED]");
  assert.equal(redact("Ключ:\neyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiDEtOTMyNDQwMDEiLCJqdGkiOizNS1lMTZlLTRiMwZjkifQ.jcwjS-oL94b5Uvj6PZS34eOakCRnROKy3E"), "[REDACTED]");
  assert.equal(redact("secret: 6C!W-ZqTN0"), "[REDACTED]");
  assert.equal(redact('Authorization:Basic RG9uYXRpb25ib3hTOikzY0gzN3ZiMmI0QkMlMjkgZiZ2Mmtz'), "[REDACTED]");
//   assert.equal(redact("DB_PASSWORD=be9NLSvOU6Sm5o23mgQqfdGh"), "[REDACTED]");
  assert.equal(redact("HTTP auth: test/test"), "[REDACTED]");
});

test("email and password pair", () => {
  assert.equal(redact('boss@gmail.com Gy2Ps&F&y7'), "[REDACTED]");
  assert.equal(redact('boss@gmail.com - Super Puper Cool man'), "boss@gmail.com - Super Puper Cool man");
  assert.equal(redact('boss@gmail.com Super Puper Cool man'), "boss@gmail.com Super Puper Cool man");
  assert.equal(redact('boss@gmail.com / Gy2Ps&F&y7'), "[REDACTED]");
  assert.equal(redact('boss@gmail.com | Gy2Ps&F&y7'), "[REDACTED]");
  assert.equal(redact('boss@gmail.com; Gy2Ps&F&y7'), "[REDACTED]");
  assert.equal(redact("boss@gmail.com\nGy2Ps&F&y7"), "[REDACTED]");
  assert.equal(redact("boss@gmail.com\n`Gy2Ps&F&y7`"), "[REDACTED]");
//   assert.equal(redact("boss@gmail.com\n`Super Puper Cool man`"), "[REDACTED]");
});

test("does not treat ordinary usernames or account names as secrets", () => {
  assert.equal(contains("username=alice"), false);
  assert.equal(contains("account=production"), false);
  assert.equal(redact("username=alice"), "username=alice");
});

test("redacts bearer token but keeps the Bearer scheme", () => {
  assert.equal(redact("Authorization: Bearer abcdefghijklmnop"), "[REDACTED]");
  assert.equal(redact("Bearer abcdefghijklmnop"), "Bearer [REDACTED]");
});

test("redacts URL credentials", () => {
  assert.equal(redact("postgres://app:very-secret-pass@db.example.com/main"), "[REDACTED]");
});

test("handles overlapping findings without corrupting offsets", () => {
  const patterns = [
    { id: "one", label: "one", regex: /secret-value/ },
    { id: "two", label: "two", regex: /value-extra/ }
  ];
  assert.equal(redact("prefix secret-value-extra suffix", { patterns }), "prefix [REDACTED] suffix");
});

test("supports ignored fenced code blocks and comments", () => {
  const text = `live=${awsKey}\n\`\`\`env\nkey=${awsKey}\n\`\`\``;
  assert.equal(scan(text, { ignoreCodeBlocks: true }).findings.length, 1);
  assert.equal(scan(`<!-- ${awsKey} -->`, { ignoreComments: true }).found, false);
});

test("sanitizes nested objects and arrays without mutating input", () => {
  const input = {
    config: { apiKey: "top-secret-value", region: "us-east-1" },
    items: [{ password: "another-secret", username: "alice" }]
  };
  const output = sanitize(input);
  assert.notEqual(output, input);
  assert.equal(output.config.apiKey, "[REDACTED]");
  assert.equal(output.config.region, "us-east-1");
  assert.equal(output.items[0].password, "[REDACTED]");
  assert.equal(output.items[0].username, "alice");
  assert.equal(input.config.apiKey, "top-secret-value");
});

test("preserves circular references in sanitized objects", () => {
  const input = { name: "agent" };
  input.self = input;
  const output = sanitize(input);
  assert.equal(output.self, output);
});

test("sanitizes sensitive keys even when their values are objects", () => {
  const output = sanitize({ credentials: { user: "alice", password: "secret" } });
  assert.equal(output.credentials, "[REDACTED]");
});

test("sanitizeWithReport counts detections without exposing values", () => {
  const result = sanitizeWithReport({ token: "abc", message: `key=${awsKey}` });
  assert.equal(result.report.found, true);
  assert.equal(result.report.findingsCount, 2);
  assert.equal(result.value.token, "[REDACTED]");
});

test("validates scan input", () => {
  assert.throws(() => scan(123), /expects a string/);
});
