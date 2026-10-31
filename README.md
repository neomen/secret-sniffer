

<p align="center">
  <img src=".github/assets/mascotte.png" alt="Secret Sniffer mascot" height="128" />
</p>

<h1 align="center">Secret Sniffer</h1>

<p align="center">
  <strong>Lightweight, zero-config secret detection and sanitization for JavaScript applications and AI agents.</strong>
</p>

<p align="center">
  Automatically detect and redact API keys, passwords, tokens, credentials, and private keys before they reach your LLMs, logs, or external services.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen.svg" alt="Zero dependencies" />
  <img src="https://img.shields.io/badge/telemetry-none-brightgreen.svg" alt="No telemetry" />
  <img src="https://img.shields.io/badge/runtime-Node.js%20%7C%20Browser-blue.svg" alt="Node.js and Browser" />
</p>

<p align="center">
  <em>Scan it. Sniff it. Keep your secrets safe.</em>
</p>

---



## Quick start (without npm)

Copy `dist/secret-sniffer.mjs` into your project:

```js
import { sanitize, redact, scan, contains } from "./secret-sniffer.mjs";

const safePrompt = sanitize(userPrompt);
const safePayload = sanitize({ prompt: userPrompt, headers });
const cleanedLog = redact(logLine);
const hasSecret = contains(text);
const findings = scan(text); // metadata only; never includes matched secret values
```

## Install from npm

```bash
npm install secret-sniffer
```

```js
import { sanitize, redact, scan } from "secret-sniffer";
```

CommonJS is also supported:

```js
const { sanitize, redact } = require("secret-sniffer");
```

## API

- `sanitize(value, options?)` — sanitizes strings, arrays, and plain objects recursively. Does not mutate the input.
- `sanitizeWithReport(value, options?)` — returns `{ value, report }`; report contains only a detection count.
- `redact(text, options?)` — replaces detected ranges in a string.
- `scan(text, options?)` — returns finding metadata (`patternId`, `label`, `index`, `length`) without secret values.
- `contains(text, options?)` — returns whether a finding exists.

Sensitive object property names such as `password`, `apiKey`, `private_key`, `accessToken`, `authorization`, `cookie`, and `credentials` cause the entire value to be replaced. Ordinary fields such as `username`, `user`, and `account` are not treated as secrets by name alone.

### Options

```js
scan(text, {
  ignoreCodeBlocks: true,
  ignoreComments: true
});

redact(text, {
  replacement: "[FILTERED]"
});
```

You can pass custom patterns:

```js
const result = scan(text, {
  patterns: [
    { id: "internal.token", label: "Internal token", regex: /INT_[A-Z0-9]{24}/ }
  ]
});
```

A pattern may optionally define `secretGroup` to identify a capture group as the secret span.

## Development

```bash
npm install
npm test
npm run build
```

Build output:

- `dist/secret-sniffer.mjs` — readable ES module
- `dist/secret-sniffer.min.mjs` — minified ES module
- `dist/secret-sniffer.cjs` — CommonJS bundle

`esbuild` is a development dependency only. The generated bundles have no runtime dependencies.

## Important limitations

Secret detection is heuristic. It recognizes known token formats and common credential assignments, but cannot guarantee detection of arbitrary or previously unseen secrets. False positives and false negatives are possible. Treat this library as a defense-in-depth filter, not as a replacement for secret management, access control, or log hygiene.

For structured values, recursive sanitization is intentionally limited to arrays and plain objects. Values such as `Date`, `Buffer`, `Map`, `Set`, and custom class instances are passed through unchanged.

Overlapping findings are merged into one redaction span. In rare partial-overlap cases, this can redact some adjacent non-secret characters rather than risk leaving part of a detected secret visible.
