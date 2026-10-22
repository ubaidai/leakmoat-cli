import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanLine, isPlaceholder } from "../src/detectors.js";
import { scan } from "../src/scan.js";
import { printReport, toJSON } from "../src/report.js";

const BIN = fileURLToPath(new URL("../bin/leakmoat.js", import.meta.url));

// Random keys generated per run, so no key-shaped strings are ever committed to this repo.
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const rand = (n) => [...randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join("");
const fake = {
  openai: () => `sk-proj-${rand(48)}`,
  anthropic: () => `sk-ant-api03-${rand(48)}`,
  gemini: () => `AIza${rand(35)}`,
  groq: () => `gsk_${rand(52)}`,
  stripe: () => `sk_live_${rand(32)}`,
  github: () => `ghp_${rand(36)}`,
  aws: () => `AKIA${rand(16).toUpperCase().replace(/[^A-Z0-9]/g, "Q")}`,
};

function gitRepo() {
  const dir = mkdtempSync(path.join(tmpdir(), "leakmoat-test-"));
  const g = (...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, stdio: "ignore" });
  g("init", "-q");
  return { dir, g };
}

test("detects each provider format", () => {
  for (const [name, make] of Object.entries(fake)) {
    const key = make();
    const hits = scanLine(`const k = "${key}";`);
    assert.equal(hits.length, 1, `${name} not detected`);
    assert.equal(hits[0].key, key);
  }
});

test("ignores placeholders and low-entropy examples", () => {
  assert.equal(scanLine('OPENAI_API_KEY="sk-proj-EXAMPLEEXAMPLEEXAMPLEEXAMPLE"').length, 0);
  assert.equal(scanLine("key: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").length, 0);
  assert.ok(isPlaceholder("sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
});

test("flags public env prefixes", () => {
  const [hit] = scanLine(`NEXT_PUBLIC_GEMINI_KEY=${fake.gemini()}`);
  assert.equal(hit.publicPrefix, true);
});

test("classifies committed, public, history, untracked and local keys", async () => {
  const { dir, g } = gitRepo();
  try {
    const keys = {
      history: fake.openai(),
      committed: fake.anthropic(),
      public: fake.gemini(),
      local: fake.groq(),
      untracked: fake.stripe(),
    };
    writeFileSync(path.join(dir, ".gitignore"), ".env.local\n");
    writeFileSync(path.join(dir, ".env"), `OPENAI_API_KEY=${keys.history}\n`);
    g("add", "-A");
    g("commit", "-qm", "add env");
    rmSync(path.join(dir, ".env"));
    mkdirSync(path.join(dir, "src"));
    writeFileSync(path.join(dir, "src", "agent.ts"), `const client = new Anthropic({ apiKey: "${keys.committed}" });\n`);
    writeFileSync(path.join(dir, ".env.production"), `NEXT_PUBLIC_GEMINI_KEY=${keys.public}\n`);
    g("add", "-A");
    g("commit", "-qm", "remove env, add agent");
    writeFileSync(path.join(dir, ".env.local"), `GROQ_API_KEY=${keys.local}\n`);
    writeFileSync(path.join(dir, "billing.js"), `stripe("${keys.untracked}")\n`);

    const result = await scan(dir);
    const byProvider = Object.fromEntries(result.findings.map((f) => [f.provider, f]));
    const exposures = (p) => byProvider[p].locations.map((l) => l.exposure);

    assert.deepEqual(exposures("OpenAI"), ["history"]);
    assert.equal(byProvider.OpenAI.locations[0].file, ".env");
    assert.ok(exposures("Anthropic").includes("committed"));
    assert.ok(exposures("Google (Gemini / Cloud)").includes("public"));
    assert.deepEqual(exposures("Groq"), ["local"]);
    assert.deepEqual(exposures("Stripe (live secret)"), ["untracked"]);
    assert.equal(result.stats.historyScanned, true);

    // The full key must never appear in any output.
    const text = printReport(result) + toJSON(result);
    for (const k of Object.values(keys)) assert.ok(!text.includes(k), "full key leaked into output");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI exit codes: 1 with exposed keys, 0 when clean", () => {
  const { dir, g } = gitRepo();
  try {
    writeFileSync(path.join(dir, "README.md"), "# hello\n");
    g("add", "-A");
    g("commit", "-qm", "init");
    let r = spawnSync(process.execPath, [BIN, "scan", dir], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /No exposed keys or secrets found/);

    writeFileSync(path.join(dir, "config.js"), `module.exports = { key: "${fake.github()}" };\n`);
    g("add", "-A");
    g("commit", "-qm", "oops");
    r = spawnSync(process.execPath, [BIN, "scan", dir, "--json"], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.equal(JSON.parse(r.stdout).atRisk, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("detects private keys and passwords in URLs, skips local dev and templates", () => {
  assert.equal(scanLine("-----BEGIN OPENSSH PRIVATE KEY-----")[0]?.detector.id, "private-key");
  assert.equal(scanLine("-----BEGIN RSA PRIVATE KEY-----")[0]?.detector.id, "private-key");

  const pass = rand(18);
  const [hit] = scanLine(`DATABASE_URL=postgresql://app:${pass}@ep-cool-db.us-east-2.aws.neon.tech/neondb`);
  assert.equal(hit?.detector.id, "url-credentials");
  const masked = hit.detector.mask(hit.key);
  assert.ok(!masked.includes(pass), "password leaked into mask");
  assert.match(masked, /postgresql:\/\/app:•••@ep-cool-db/);

  assert.equal(scanLine("DATABASE_URL=postgres://postgres:postgres@localhost:5432/app").length, 0);
  assert.equal(scanLine("url = `postgres://${user}:${pass}@${host}/db`").length, 0);
  assert.equal(scanLine("redis://default:password@redis.example.com").length, 0);
});
