import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanChanges } from "../src/scan.js";
import { installHook } from "../src/hook.js";

const BIN = fileURLToPath(new URL("../bin/leakmoat.js", import.meta.url));
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rand = (n) => [...randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join("");
const openaiKey = () => `sk-proj-${rand(48)}`;

function repo() {
  const dir = mkdtempSync(path.join(tmpdir(), "leakmoat-hook-"));
  const g = (...args) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args], {
      cwd: dir,
      stdio: "pipe",
      encoding: "utf8",
    });
  g("init", "-q");
  writeFileSync(path.join(dir, "README.md"), "# demo\n");
  g("add", "-A");
  g("commit", "-qm", "init");
  return { dir, g };
}

test("--staged finds a key in staged changes, with its line number, and ignores unstaged edits", async () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "agent.js"), `const a = 1;\nconst key = "${openaiKey()}";\n`);
    g("add", "agent.js");
    writeFileSync(path.join(dir, "notes.js"), `const other = "${openaiKey()}";\n`); // not staged

    const result = await scanChanges(dir, "staged");
    assert.equal(result.findings.length, 1);
    assert.deepEqual(result.findings[0].locations, [{ file: "agent.js", line: 2, exposure: "staged" }]);

    const r = spawnSync(process.execPath, [BIN, "scan", dir, "--staged"], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /commit blocked/);
    assert.match(r.stderr, /nothing to rotate yet/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--staged passes clean changes and honours leakmoat:ignore", async () => {
  const { dir, g } = repo();
  try {
    writeFileSync(path.join(dir, "fixture.js"), `const fake = "${openaiKey()}"; // leakmoat:ignore\n`);
    g("add", "fixture.js");
    const result = await scanChanges(dir, "staged");
    assert.equal(result.findings.length, 0);
    const r = spawnSync(process.execPath, [BIN, "scan", dir, "--staged"], { encoding: "utf8" });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /no secrets in 1 staged file/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--push only checks commits that are not on a remote yet", async () => {
  const { dir, g } = repo();
  const remote = mkdtempSync(path.join(tmpdir(), "leakmoat-remote-"));
  try {
    execFileSync("git", ["init", "-q", "--bare", remote]);
    g("remote", "add", "origin", remote);
    g("push", "-q", "origin", "HEAD:refs/heads/main");
    g("fetch", "-q", "origin");

    writeFileSync(path.join(dir, "config.js"), `export const key = "${openaiKey()}";\n`);
    g("add", "-A");
    g("commit", "-qm", "add config");

    let result = await scanChanges(dir, "push");
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].locations[0].exposure, "unpushed");
    assert.equal(result.stats.commits, 1);

    g("push", "-q", "origin", "HEAD:refs/heads/main");
    g("fetch", "-q", "origin");
    result = await scanChanges(dir, "push");
    assert.equal(result.findings.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(remote, { recursive: true, force: true });
  }
});

test("install-hook writes a hook, refuses to overwrite a foreign one, and git refuses the commit", () => {
  const { dir, g } = repo();
  const shimDir = mkdtempSync(path.join(tmpdir(), "leakmoat-shim-"));
  try {
    // Foreign hook is left alone.
    const hooks = path.join(dir, ".git", "hooks");
    mkdirSync(hooks, { recursive: true });
    writeFileSync(path.join(hooks, "pre-commit"), "#!/bin/sh\necho mine\n");
    assert.equal(installHook(dir, { version: "0.0.0" }).status, "exists");
    assert.equal(readFileSync(path.join(hooks, "pre-commit"), "utf8"), "#!/bin/sh\necho mine\n");

    // Forced install, then an update of our own hook.
    assert.equal(installHook(dir, { version: "0.0.0", force: true }).status, "updated");
    assert.equal(installHook(dir, { version: "0.0.0" }).status, "updated");
    assert.match(readFileSync(path.join(hooks, "pre-commit"), "utf8"), /leakmoat scan --staged/);

    // End to end: a `leakmoat` on PATH (this checkout) runs from the hook and blocks the commit.
    const node = process.execPath.replace(/\\/g, "/");
    const bin = BIN.replace(/\\/g, "/");
    writeFileSync(path.join(shimDir, "leakmoat"), `#!/bin/sh\nexec "${node}" "${bin}" "$@"\n`);
    chmodSync(path.join(shimDir, "leakmoat"), 0o755);
    const env = { ...process.env, PATH: `${shimDir}${path.delimiter}${process.env.PATH}` };

    writeFileSync(path.join(dir, "leak.js"), `const k = "${openaiKey()}";\n`);
    g("add", "leak.js");
    const blocked = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "leak"], { cwd: dir, env, encoding: "utf8" });
    assert.notEqual(blocked.status, 0, "commit with a secret should be refused");
    assert.match(blocked.stderr, /commit blocked/);

    writeFileSync(path.join(dir, "leak.js"), "const k = process.env.OPENAI_API_KEY;\n");
    g("add", "leak.js");
    const ok = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "fixed"], { cwd: dir, env, encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(shimDir, { recursive: true, force: true });
  }
});
