#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { scan, scanChanges } from "../src/scan.js";
import { hasRisk, printReport, toJSON } from "../src/report.js";
import { hookCommand, installHook } from "../src/hook.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

const HELP = `leakmoat ${pkg.version}
Find leaked API keys in your code and git history. Runs locally; nothing is sent anywhere.

Usage
  npx leakmoat scan [dir]            Scan files and full git history
  npx leakmoat scan --staged         Scan only staged changes (for a pre-commit hook)
  npx leakmoat scan --push           Scan only commits not pushed yet (for a pre-push hook)
  npx leakmoat install-hook          Block commits that contain a secret
  npx leakmoat install-hook --pre-push

Options
  --no-history   Skip git history (faster, but misses deleted keys)
  --json         Machine-readable output
  --force        install-hook: replace an existing hook
  -h, --help     Show this help
  -v, --version  Show version

False positive? Add a leakmoat:ignore comment on that line.

Exit codes
  0  no exposed keys    1  exposed keys found    2  error

https://leakmoat.com`;

function parse(argv) {
  const opts = { cmd: "scan", dir: ".", history: true, json: false, mode: null, prePush: false, force: false };
  const rest = [];
  for (const a of argv) {
    if (a === "-h" || a === "--help") opts.cmd = "help";
    else if (a === "-v" || a === "--version") opts.cmd = "version";
    else if (a === "--no-history") opts.history = false;
    else if (a === "--json") opts.json = true;
    else if (a === "--staged") opts.mode = "staged";
    else if (a === "--push" || a === "--unpushed") opts.mode = "push";
    else if (a === "--pre-push") opts.prePush = true;
    else if (a === "--force") opts.force = true;
    else if (a.startsWith("-")) throw new Error(`Unknown option ${a}. Run with --help.`);
    else rest.push(a);
  }
  if (rest[0] === "scan") rest.shift();
  else if (rest[0] === "install-hook") (opts.cmd = "install-hook"), rest.shift();
  else if (rest[0] === "help") (opts.cmd = "help"), rest.shift();
  if (rest[0]) opts.dir = rest[0];
  return opts;
}

function runInstallHook(opts) {
  const mode = opts.prePush ? "pre-push" : "pre-commit";
  const { file, status } = installHook(opts.dir, { mode, version: pkg.version, force: opts.force });
  if (status === "exists") {
    console.log(`A ${mode} hook already exists at ${file}, so it was left alone.
Add these lines to it (or to your Husky / lefthook config), or rerun with --force to replace it:

${hookCommand(mode, pkg.version)}`);
    return 2;
  }
  console.log(`leakmoat ${status} ${file}
Every ${mode === "pre-push" ? "push" : "commit"} is now checked for API keys and secrets. Nothing leaves your machine.`);
  return 0;
}

async function main() {
  const opts = parse(process.argv.slice(2));
  if (opts.cmd === "help") return console.log(HELP), 0;
  if (opts.cmd === "version") return console.log(pkg.version), 0;
  if (opts.cmd === "install-hook") return runInstallHook(opts);

  if (opts.mode) {
    const result = await scanChanges(opts.dir, opts.mode);
    const output = opts.json ? toJSON(result) : printReport(result);
    // A blocked commit goes to stderr so git shows it; JSON always goes to stdout for tools.
    (hasRisk(result) && !opts.json ? console.error : console.log)(output);
    return hasRisk(result) ? 1 : 0;
  }

  const progress = !opts.json && process.stderr.isTTY;
  const result = await scan(opts.dir, {
    history: opts.history,
    onProgress: progress ? (m) => process.stderr.write(`\r\x1b[2K${m}...`) : undefined,
  });
  if (progress) process.stderr.write("\r\x1b[2K");

  console.log(opts.json ? toJSON(result) : printReport(result));
  return hasRisk(result) ? 1 : 0;
}

// Set exitCode instead of calling process.exit(), which can truncate piped output on Windows.
main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(`leakmoat: ${err.message}`);
    process.exitCode = 2;
  },
);
