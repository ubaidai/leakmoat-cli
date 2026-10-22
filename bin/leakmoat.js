#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { scan } from "../src/scan.js";
import { hasRisk, printReport, toJSON } from "../src/report.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

const HELP = `leakmoat ${pkg.version}
Find leaked API keys in your code and git history. Runs locally; nothing is sent anywhere.

Usage
  npx leakmoat scan [dir]

Options
  --no-history   Skip git history (faster, but misses deleted keys)
  --json         Machine-readable output
  -h, --help     Show this help
  -v, --version  Show version

Exit codes
  0  no exposed keys    1  exposed keys found    2  error

https://leakmoat.com`;

function parse(argv) {
  const opts = { cmd: "scan", dir: ".", history: true, json: false };
  const rest = [];
  for (const a of argv) {
    if (a === "-h" || a === "--help") opts.cmd = "help";
    else if (a === "-v" || a === "--version") opts.cmd = "version";
    else if (a === "--no-history") opts.history = false;
    else if (a === "--json") opts.json = true;
    else if (a.startsWith("-")) throw new Error(`Unknown option ${a}. Run with --help.`);
    else rest.push(a);
  }
  if (rest[0] === "scan") rest.shift();
  else if (rest[0] === "help") (opts.cmd = "help"), rest.shift();
  if (rest[0]) opts.dir = rest[0];
  return opts;
}

async function main() {
  const opts = parse(process.argv.slice(2));
  if (opts.cmd === "help") return console.log(HELP), 0;
  if (opts.cmd === "version") return console.log(pkg.version), 0;

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
