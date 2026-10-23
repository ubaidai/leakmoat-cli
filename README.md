# leakmoat

[![npm](https://img.shields.io/npm/v/leakmoat)](https://www.npmjs.com/package/leakmoat) [![test](https://github.com/ubaidai/leakmoat-cli/actions/workflows/test.yml/badge.svg)](https://github.com/ubaidai/leakmoat-cli/actions/workflows/test.yml)

Find leaked API keys in your code **and your git history**. One command, runs on your machine, sends nothing anywhere.

```bash
npx leakmoat scan
```

```
✖ 2 exposed secrets: rotate these now

  ● OpenAI  sk-proj-…3f9a
      .env (commit 4e1c2a07, 2026-09-11)
      Why: deleted from the files but still in git history; every clone has it.
      Rotate: https://platform.openai.com/api-keys

  ● Google (Gemini / Cloud)  AIzaSy…k21Q
      .env.production:3
      Why: uses a public env prefix, so it ships to every visitor's browser.
      Rotate: https://aistudio.google.com/app/apikey
```

## What it checks

| Where | Why it matters |
|---|---|
| Files committed right now | Anyone with repo access can read them |
| **Full git history** | Deleting a `.env` does not delete it. Every clone and fork still has the key |
| `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_` variables | Frameworks ship these to every visitor's browser |
| Files not committed yet | One `git add .` away from being leaked |
| Gitignored local files | Listed as fine, so you know what exists |

**Detects:** OpenAI, Anthropic, Google Gemini / Cloud, Groq, xAI, OpenRouter, Perplexity, Hugging Face, Replicate, Fireworks, Stripe live keys, GitHub tokens, AWS access keys, Slack, Resend, SendGrid, npm tokens, private keys, and passwords inside URLs (like `DATABASE_URL`).

## Built to be trusted

- **Zero dependencies.** Read every line before you run it: `bin/` and `src/` are about 850 lines.
- **No network calls.** No telemetry, no "checking for updates", nothing.
- **Never prints a full key.** Output shows a masked form like `sk-proj-…3f9a`. Keys are grouped by SHA-256, so the same key across ten files shows up once.
- **Verifiable releases.** Every version is published from GitHub Actions through npm Trusted Publishing with provenance. No npm token exists, and npm shows which commit each release was built from.
- Skips obvious placeholders like `sk-proj-EXAMPLE…` and local dev URLs like `postgres://postgres:postgres@localhost`.

## Options

```bash
npx leakmoat scan [dir]     # default: current directory
npx leakmoat scan --json    # machine-readable output
npx leakmoat scan --no-history   # skip git history (faster, misses deleted keys)
npx leakmoat scan --staged       # only staged changes (what a pre-commit hook runs)
npx leakmoat scan --push         # only commits not pushed yet (what a pre-push hook runs)
npx leakmoat scan --since main   # only commits after a branch or commit (pull requests, CI)
```

Exit code `1` when exposed secrets are found, so it works in CI:

```yaml
- run: npx leakmoat scan
```

## Block secrets before they leave your machine

Catch a key at commit time, before it ever reaches git history:

```bash
npx leakmoat install-hook             # pre-commit: checks only your staged changes
npx leakmoat install-hook --pre-push  # pre-push: checks only commits not pushed yet
```

```
✖ leakmoat: commit blocked, 1 secret in your staged changes

  ● OpenAI  sk-proj-…3f9a
      src/agent.ts:4

Good news: it has not left your machine, so there is nothing to rotate yet.
  1. Move the value to an env var or secret store, then `git add` the file again.
  2. False positive? Add a `leakmoat:ignore` comment on that line.
```

- Hook mode scans only the change, so it is fast and never blocks you over old keys elsewhere in the repo.
- An existing hook (Husky, lefthook) is never overwritten. Add `npx leakmoat scan --staged` to it instead.
- With the [pre-commit](https://pre-commit.com) framework:

```yaml
- repo: https://github.com/ubaidai/leakmoat-cli
  rev: v0.3.1
  hooks:
    - id: leakmoat
```

## GitHub Action

Fails a pull request that adds a secret, with the finding shown inline on the diff and a summary on the run page:

```yaml
# .github/workflows/leakmoat.yml
name: leakmoat
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # needed to compare against the base branch
      - uses: ubaidai/leakmoat-cli@v0
```

- On a pull request it checks only the PR's commits, and on a push only the pushed commits, so old keys elsewhere never fail a check. Use `scope: full` to scan the whole repo and its history.
- `fail-on-findings: false` reports without failing the job. The `found` output is `"true"` when something was found.
- Runs the code in this repository on the runner itself: nothing is sent anywhere.

## Found something?

1. **Rotate it** with the link in the output. Rewriting git history is not enough: once a key was pushed, assume it was copied.
2. Store the new key in your deploy platform's secrets, not in code or a public env variable.
3. Set a monthly spend limit on every AI provider.

Want alerts when a key leaks or starts burning money, and rotation across Railway and Vercel in one pass? [leakmoat.com](https://leakmoat.com/?ref=npm)

## License

MIT
