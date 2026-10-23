// Key formats Leakmoat detects. Order matters: specific prefixes before generic ones,
// because overlapping matches on the same line are resolved first-come.

/**
 * @typedef {{
 *   id: string,
 *   provider: string,
 *   pattern: RegExp,
 *   rotateUrl?: string,
 *   rotateHint?: string,
 *   skipEntropy?: boolean,
 *   validate?: (match: RegExpMatchArray) => boolean,
 *   mask?: (key: string) => string,
 * }} Detector
 */

/** @type {Detector[]} */
export const DETECTORS = [
  {
    id: "anthropic",
    provider: "Anthropic",
    pattern: /sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g,
    rotateUrl: "https://console.anthropic.com/settings/keys",
  },
  {
    id: "openrouter",
    provider: "OpenRouter",
    pattern: /sk-or-v1-[A-Za-z0-9]{32,}/g,
    rotateUrl: "https://openrouter.ai/settings/keys",
  },
  {
    id: "openai",
    provider: "OpenAI",
    pattern: /sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/g,
    rotateUrl: "https://platform.openai.com/api-keys",
  },
  {
    id: "openai-legacy",
    provider: "OpenAI",
    pattern: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,
    rotateUrl: "https://platform.openai.com/api-keys",
  },
  {
    id: "gemini",
    provider: "Google (Gemini / Cloud)",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    rotateUrl: "https://aistudio.google.com/app/apikey",
  },
  {
    id: "groq",
    provider: "Groq",
    pattern: /\bgsk_[A-Za-z0-9]{40,}\b/g,
    rotateUrl: "https://console.groq.com/keys",
  },
  {
    id: "xai",
    provider: "xAI",
    pattern: /\bxai-[A-Za-z0-9]{40,}\b/g,
    rotateUrl: "https://console.x.ai",
  },
  {
    id: "perplexity",
    provider: "Perplexity",
    pattern: /\bpplx-[A-Za-z0-9]{40,}\b/g,
    rotateUrl: "https://www.perplexity.ai/settings/api",
  },
  {
    id: "huggingface",
    provider: "Hugging Face",
    pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
    rotateUrl: "https://huggingface.co/settings/tokens",
  },
  {
    id: "replicate",
    provider: "Replicate",
    pattern: /\br8_[A-Za-z0-9]{37}\b/g,
    rotateUrl: "https://replicate.com/account/api-tokens",
  },
  {
    id: "fireworks",
    provider: "Fireworks AI",
    pattern: /\bfw_[A-Za-z0-9]{24,}\b/g,
    rotateUrl: "https://fireworks.ai/account/api-keys",
  },
  {
    id: "stripe-live",
    provider: "Stripe (live secret)",
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/g,
    rotateUrl: "https://dashboard.stripe.com/apikeys",
  },
  {
    id: "github",
    provider: "GitHub token",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g,
    rotateUrl: "https://github.com/settings/tokens",
  },
  {
    id: "aws",
    provider: "AWS access key",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    rotateUrl: "https://console.aws.amazon.com/iam/home#/security_credentials",
  },
  {
    id: "slack",
    provider: "Slack token",
    pattern: /\bxox[abpr]-[A-Za-z0-9-]{20,}\b/g,
    rotateUrl: "https://api.slack.com/apps",
  },
  {
    id: "resend",
    provider: "Resend",
    pattern: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b/g,
    rotateUrl: "https://resend.com/api-keys",
  },
  {
    id: "sendgrid",
    provider: "SendGrid",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    rotateUrl: "https://app.sendgrid.com/settings/api_keys",
  },
  {
    id: "private-key",
    provider: "Private key",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    rotateHint: "Generate a new key pair, replace it wherever the public key is installed, then delete this one",
    skipEntropy: true,
    // A real key: the header alone on its line (PEM file), or followed by key data inside a
    // string (e.g. "-----BEGIN PRIVATE KEY-----\nMIIE..." in a service-account JSON).
    // Code that merely mentions the header, like startsWith("-----BEGIN ..."), is not a key.
    validate: (m) => {
      if (m.input.trim() === m[0]) return true;
      return /^\\n[A-Za-z0-9+/=]{40,}/.test(m.input.slice((m.index ?? 0) + m[0].length));
    },
    mask: (k) => k.replace(/-/g, "").trim(),
  },
  {
    id: "url-credentials",
    provider: "Password in a URL",
    pattern: /\b[a-z][a-z0-9+.-]{1,20}:\/\/([^\s:@\/'"`]+):([^\s@\/'"`]{3,})@([^\s\/:'"`?#]+)/gi,
    rotateHint: "Change this password at the service in the URL, then update it in your deploy platform's secrets",
    skipEntropy: true,
    validate: (m) => {
      const [, , pass, host] = m;
      if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|db|postgres|mysql|redis|mongo|example\.(com|org))$/i.test(host)) return false;
      if (/^(password|pass|passwd|secret|changeme|postgres|root|user|test|xxx+|\*+|\.{2,}|…+|•+)$/i.test(pass)) return false; // "..." in docs
      if (/[$%{<]/.test(pass)) return false; // ${VAR}, %s, {{x}}, <password> templates
      return true;
    },
    mask: (k) => k.replace(/:\/\/([^:]+):[^@]+@/, "://$1:•••@"),
  },
  {
    id: "npm",
    provider: "npm token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    rotateUrl: "https://www.npmjs.com/settings/~/tokens",
  },
];

// Env var prefixes that frameworks inline into client-side JavaScript.
export const PUBLIC_PREFIX = /\b(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)[A-Z0-9_]*\s*[:=]/;

// Obvious placeholders and docs examples, never reported.
const PLACEHOLDER = /(EXAMPLE|DEMOonly|PLACEHOLDER|placeholder|your[_-]?(api[_-]?)?key|xxxxxxxx|XXXXXXXX|0000000000|1234567890|abcdefghij|<[^>]*>|\.\.\.)/;

/** Shannon entropy in bits per character. Real keys are random; examples often are not. */
export function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function isPlaceholder(key) {
  // Short keys (AWS: 20 chars, uppercase only) are naturally less random than long ones,
  // so the bar scales with length. A flat 3.2 silently missed about 1 in 300 real AWS keys.
  return PLACEHOLDER.test(key) || entropy(key) < (key.length >= 32 ? 3.0 : 2.5);
}

/** Shows enough to recognise a key without revealing it. */
/**
 * Shows the key's type prefix (sk-proj-, sk_live_, gsk_) and its last 4 characters, nothing else.
 * The prefix is everything up to the last - or _ in the first 10 characters; otherwise 6 characters.
 */
export function maskKey(key) {
  const head = key.slice(0, 10);
  const cut = Math.max(head.lastIndexOf("-"), head.lastIndexOf("_"));
  const headLen = cut >= 2 ? cut + 1 : Math.min(6, key.length - 4);
  return `${key.slice(0, headLen)}…${key.slice(-4)}`;
}

/**
 * Finds keys in one line of text.
 * @returns {{ detector: Detector, key: string, publicPrefix: boolean }[]}
 */
export function scanLine(line) {
  // An explicit `leakmoat:ignore` comment on the line marks a known false positive.
  if (/leakmoat[:-]ignore/i.test(line)) return [];
  if (line.length > 5000) line = line.slice(0, 5000); // minified bundles
  const results = [];
  const taken = [];
  for (const d of DETECTORS) {
    d.pattern.lastIndex = 0;
    for (const m of line.matchAll(d.pattern)) {
      const start = m.index ?? 0;
      const end = start + m[0].length;
      if (taken.some(([s, e]) => start < e && end > s)) continue;
      taken.push([start, end]);
      if (d.validate && !d.validate(m)) continue;
      if (!d.skipEntropy && isPlaceholder(m[0])) continue;
      results.push({ detector: d, key: m[0], publicPrefix: PUBLIC_PREFIX.test(line) });
    }
  }
  return results;
}
