import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import { maskKey, scanLine } from "./detectors.js";

// Directories that are never worth scanning (dependencies, build output, VCS internals).
const SKIP_DIRS = new Set([
  ".git", "node_modules", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel", ".cache",
  "dist", "build", "out", "coverage", "vendor", ".venv", "venv", "__pycache__", "target", ".gradle",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|7z|rar|mp[34]|mov|woff2?|ttf|otf|eot|exe|dll|so|dylib|bin|lockb|sqlite|db)$/i;

/**
 * Where a key was seen. Severity order: committed and public are worst, local is fine.
 * @typedef {"committed" | "public" | "history" | "untracked" | "local"} Exposure
 * @typedef {{ file: string, line?: number, commit?: string, date?: string, exposure: Exposure }} Location
 * @typedef {{ fingerprint: string, provider: string, masked: string, rotateUrl?: string, rotateHint?: string, locations: Location[] }} Finding
 */

export const EXPOSURE_RANK = { committed: 0, public: 1, history: 2, untracked: 3, local: 4 };

function git(cwd, args) {
  const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

export function isGitRepo(dir) {
  return git(dir, ["rev-parse", "--is-inside-work-tree"])?.trim() === "true";
}

function gitFileSet(root, args) {
  const out = git(root, ["ls-files", "-z", ...args]);
  return new Set(out ? out.split("\0").filter(Boolean).map((p) => p.replace(/\\/g, "/")) : []);
}

async function* walk(dir, root) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(full, root);
    } else if (e.isFile() && !BINARY_EXT.test(e.name)) {
      yield path.relative(root, full).replace(/\\/g, "/");
    }
  }
}

async function scanFile(fullPath, onMatch) {
  const stat = await fs.stat(fullPath).catch(() => null);
  if (!stat || stat.size > MAX_FILE_BYTES) return;
  const rl = createInterface({ input: createReadStream(fullPath, { encoding: "utf8" }), crlfDelay: Infinity });
  let n = 0;
  for await (const line of rl) {
    n++;
    if (line.includes("\0")) return; // binary content
    for (const hit of scanLine(line)) onMatch(hit, n);
  }
}

/** Streams `git log -p` over every branch and reports keys on added lines. */
function scanHistory(root, onMatch, onProgress) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "git",
      ["-C", root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "--unified=0", "--format=%x00%H %aI"],
      { stdio: ["ignore", "pipe", "ignore"] },
    );
    const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
    let commit = "";
    let date = "";
    let file = "";
    let commits = 0;
    rl.on("line", (line) => {
      if (line.startsWith("\0")) {
        [commit, date] = line.slice(1).split(" ");
        commits++;
        if (commits % 200 === 0) onProgress?.(commits);
      } else if (line.startsWith("+++ ")) {
        file = line.startsWith("+++ b/") ? line.slice(6) : "";
      } else if (line.startsWith("+") && file) {
        for (const hit of scanLine(line.slice(1))) onMatch(hit, { file, commit, date });
      }
    });
    child.on("error", reject);
    child.on("close", () => resolve(commits));
  });
}

const fingerprint = (key) => createHash("sha256").update(key).digest("hex");

/**
 * Scans a directory. Never stores or returns a full key: only its SHA-256 and a masked form.
 * @param {string} root
 * @param {{ history?: boolean, onProgress?: (msg: string) => void }} [opts]
 */
export async function scan(root, opts = {}) {
  root = path.resolve(root);
  const repo = isGitRepo(root);
  /** @type {Map<string, Finding>} */
  const findings = new Map();
  const stats = { files: 0, commits: 0, repo, historyScanned: false };

  const record = (hit, loc) => {
    const fp = fingerprint(hit.key);
    let f = findings.get(fp);
    if (!f) {
      f = { fingerprint: fp, provider: hit.detector.provider, masked: hit.detector.mask?.(hit.key) ?? maskKey(hit.key), rotateUrl: hit.detector.rotateUrl, rotateHint: hit.detector.rotateHint, locations: [] };
      findings.set(fp, f);
    }
    const exposure = hit.publicPrefix && loc.exposure !== "history" ? "public" : loc.exposure;
    const dup = f.locations.some((l) => l.file === loc.file && l.line === loc.line && l.commit === loc.commit);
    if (!dup) f.locations.push({ ...loc, exposure });
  };

  // 1. Working tree
  const tracked = repo ? gitFileSet(root, ["--cached"]) : new Set();
  const untracked = repo ? gitFileSet(root, ["--others", "--exclude-standard"]) : new Set();
  for await (const rel of walk(root, root)) {
    stats.files++;
    if (stats.files % 500 === 0) opts.onProgress?.(`Scanned ${stats.files} files`);
    const exposure = !repo ? "untracked" : tracked.has(rel) ? "committed" : untracked.has(rel) ? "untracked" : "local";
    await scanFile(path.join(root, rel), (hit, line) => record(hit, { file: rel, line, exposure }));
  }

  // 2. Git history: keys that were committed once stay readable forever, even after deletion.
  if (repo && opts.history !== false) {
    opts.onProgress?.("Scanning git history");
    const currentlyCommitted = new Set();
    for (const f of findings.values()) {
      if (f.locations.some((l) => l.exposure === "committed" || l.exposure === "public")) currentlyCommitted.add(f.fingerprint);
    }
    stats.commits = await scanHistory(
      root,
      (hit, { file, commit, date }) => {
        const fp = fingerprint(hit.key);
        // A key that is still committed is already reported at its current location.
        if (currentlyCommitted.has(fp)) return;
        const existing = findings.get(fp);
        if (existing?.locations.some((l) => l.exposure === "history")) return; // first sighting is enough
        record(hit, { file, commit: commit.slice(0, 8), date: date?.slice(0, 10), exposure: "history" });
      },
      (n) => opts.onProgress?.(`Scanned ${n} commits`),
    );
    stats.historyScanned = true;
  }

  const list = [...findings.values()].sort((a, b) => worst(a) - worst(b));
  return { root, stats, findings: list };
}

export function worst(f) {
  return Math.min(...f.locations.map((l) => EXPOSURE_RANK[l.exposure]));
}
