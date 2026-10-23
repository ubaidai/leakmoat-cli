import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanChanges } from "../src/scan.js";
import { toAnnotations, toMarkdown } from "../src/report.js";

const BIN = fileURLToPath(new URL("../bin/leakmoat.js", import.meta.url));
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rand = (n) => [...randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join("");
const key = () => `sk-proj-${rand(48)}`;

function repo() {
  const dir = mkdtempSync(path.join(tmpdir(), "leakmoat-ci-"));
  const g = (...args) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" }).trim();
  g("init", "-q");
  return { dir, g };
}

test("--since only reports keys added after the ref, and old keys never fail the check", async () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "old.js"), `const legacy = "${key()}";\n`); // already on main
    g("add", "-A");
    g("commit", "-qm", "main");
    const base = g("rev-parse", "HEAD");

    writeFileSync(path.join(dir, "feature.js"), `const ok = 1;\nconst k = "${key()}";\n`);
    g("add", "-A");
    g("commit", "-qm", "feature");

    const result = await scanChanges(dir, "range", base);
    assert.equal(result.findings.length, 1);
    assert.deepEqual(result.findings[0].locations.map((l) => [l.file, l.line, l.exposure]), [["feature.js", 2, "new"]]);
    assert.equal(result.stats.commits, 1);

    const clean = await scanChanges(dir, "range", "HEAD");
    assert.equal(clean.findings.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--since rejects refs that are missing or look like options", async () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "a.txt"), "a\n");
    g("add", "-A");
    g("commit", "-qm", "a");
    await assert.rejects(scanChanges(dir, "range", "does-not-exist"), /fetch-depth: 0/);
    await assert.rejects(scanChanges(dir, "range", "--output=/tmp/x"), /cannot find/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("annotations and job summary point at the line, mask the key, and tell you to rotate", () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "README.md"), "hi\n");
    g("add", "-A");
    g("commit", "-qm", "init");
    const base = g("rev-parse", "HEAD");
    const k = key();
    writeFileSync(path.join(dir, "agent, v2.ts"), `x\nconst k = "${k}";\n`); // comma in a name must be escaped
    g("add", "-A");
    g("commit", "-qm", "leak");

    const summary = path.join(dir, "summary.md");
    const r = spawnSync(process.execPath, [BIN, "scan", dir, "--since", base, "--annotations", "--summary", summary], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /^::error file=agent%2C v2\.ts,line=2,title=Leaked OpenAI secret::sk-proj-…/m);
    assert.match(r.stdout, /Rotate it%3A|Rotate it: https:\/\/platform\.openai\.com/);
    assert.match(r.stderr, /check failed/);
    assert.match(r.stderr, /already pushed, so treat each key as exposed/);

    const md = readFileSync(summary, "utf8");
    assert.match(md, /1 exposed secret/);
    assert.match(md, /\[Rotate\]\(https:\/\/platform\.openai\.com\/api-keys\)/);
    for (const out of [r.stdout, r.stderr, md]) assert.ok(!out.includes(k), "full key leaked into CI output");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("clean results produce no annotations and a green summary", async () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "a.txt"), "nothing here\n");
    g("add", "-A");
    g("commit", "-qm", "a");
    const result = await scanChanges(dir, "range", "HEAD");
    assert.equal(toAnnotations(result), "");
    assert.match(toMarkdown(result), /No exposed secrets/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("file names with spaces and non-ASCII characters are reported exactly", async () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "README.md"), "hi\n");
    g("add", "-A");
    g("commit", "-qm", "init");
    const base = g("rev-parse", "HEAD");
    writeFileSync(path.join(dir, "café config.js"), `const k = "${key()}";\n`);
    g("add", "-A");
    g("commit", "-qm", "unicode");
    const result = await scanChanges(dir, "range", base);
    assert.equal(result.findings[0].locations[0].file, "café config.js");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
