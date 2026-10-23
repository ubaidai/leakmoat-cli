import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const MARKER = "# Installed by leakmoat";

/** The command a hook runs: a local install if there is one, otherwise the pinned npm version. */
export function hookCommand(mode, version) {
  const flag = mode === "pre-push" ? "--push" : "--staged";
  return `if command -v leakmoat >/dev/null 2>&1; then
  exec leakmoat scan ${flag}
else
  exec npx --yes leakmoat@${version} scan ${flag}
fi`;
}

/**
 * Writes .git/hooks/pre-commit (or pre-push). Respects core.hooksPath. Never overwrites a hook
 * leakmoat did not create, unless force is set.
 * @returns {{ file: string, status: "installed" | "updated" | "exists" }}
 */
export function installHook(dir, { mode = "pre-commit", version, force = false }) {
  const r = spawnSync("git", ["-C", dir, "rev-parse", "--git-path", "hooks"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error("not a git repository");
  const hooksDir = path.resolve(dir, r.stdout.trim());
  const file = path.join(hooksDir, mode);

  let status = "installed";
  if (existsSync(file)) {
    const current = readFileSync(file, "utf8");
    if (!current.includes(MARKER) && !force) return { file, status: "exists" };
    status = "updated";
  }
  mkdirSync(hooksDir, { recursive: true });
  const script = `#!/bin/sh
${MARKER} (https://leakmoat.com). Delete this file to uninstall.
# Blocks the ${mode === "pre-push" ? "push" : "commit"} if it contains an API key or other secret.
${hookCommand(mode, version)}
`;
  writeFileSync(file, script, { mode: 0o755 });
  chmodSync(file, 0o755);
  return { file, status };
}
