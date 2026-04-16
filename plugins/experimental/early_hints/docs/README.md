# HTTP 103 Early Hints Plugin

Remap plugin for Apache Traffic Server that sends **HTTP 103 Early Hints** responses to HTTP/2 clients before the final response, enabling browsers to preload critical resources and significantly reduce page load times.

---

## Table of Contents

- [Overview](#overview)
- [Operating Modes](#operating-modes)
- [Configuration](#configuration)
- [Request Processing Flow](#request-processing-flow)
- [HTML Scanner](#html-scanner)
- [Hints Cache](#hints-cache)
- [Disk Persistence](#disk-persistence)
- [Security Features](#security-features)
- [Statistics](#statistics)
- [Examples](#examples)

---

## Overview

When a browser requests an HTML page, it normally has to wait for the full response before it discovers which CSS, JS, and fonts to load. HTTP 103 Early Hints solves this by sending a preliminary response *before* the origin responds:

```
Browser                     ATS (CDN)                   Origin
   │── GET /page.html ──────►│                              │
   │                          │── GET /page.html ──────────►│
   │◄── 103 Early Hints ─────│  (instant, from cache)       │
   │    Link: </style.css>    │                              │
   │    Link: </app.js>       │                              │
   │                          │                              │
   │  ★ Browser starts        │                              │
   │    preloading resources  │                              │
   │                          │◄── 200 OK ──────────────────│
   │◄── 200 OK ──────────────│                              │
   │    (page HTML body)      │                              │
```

**Key benefits:**
- Resources start loading ~200-800ms earlier (saved = origin response time)
- Zero impact on cache miss / first request (only sends when hints are cached)
- No browser-side code changes needed (browser support: Chrome 103+, Firefox 102+)
- Works only over HTTP/2 (protocol requirement)

---

## Operating Modes

The plugin supports three modes that can be combined:

### `manual`
Admin specifies Link header values directly in the remap rule. Hints are sent immediately on every qualifying request — no learning needed.

### `auto-learn`
Plugin scans the HTML `<head>` of origin responses via a streaming transform. Discovered preloadable resources (`<link rel=preload>`, `<link rel=stylesheet>`, `<link rel=modulepreload>`, `<script src>`) are cached and served as 103 hints on subsequent requests.

### `origin-forward`
Plugin extracts `Link` headers from origin responses, caches them, and serves as 103 hints on subsequent requests. Useful when the origin already sends Link headers.

### Combined Modes
Modes can be combined with commas:

- `auto-learn,origin-forward` — Both sources learn and write to the same cache independently. **Important:** `put()` is a full replace — links are not merged. Write order: origin-forward writes first (at origin response arrival in READ_RESPONSE_HDR), auto-learn writes later (after the HTML body transform completes). This means **auto-learn is always the last writer** and its results overwrite origin-forward results for the same URL.

- `manual,auto-learn` — Manual links are sent immediately in both 103 and the final 200 responses. Auto-learn still runs in the background: it scans HTML and writes to cache as normal, but the cached hints are **not used for serving** while manual is active. **Practical use case:** bootstrapping — use manual for immediate reliability while auto-learn silently warms the cache. When you're confident the cache is stable, switch to `auto-learn` mode with zero cold-start penalty.

- `manual,auto-learn,origin-forward` — Manual links sent in responses; both auto-learn and origin-forward learn in the background (same last-writer-wins overwrite behavior as `auto-learn,origin-forward`).

---

## Configuration

The plugin is configured per remap rule using `@pparam`. Two formats are supported:

**Standard format** (two `@pparam` per option — one for key, one for value):
```
map /path http://origin @plugin=early_hints.so @pparam=--mode @pparam=auto-learn @pparam=--max-links @pparam=15
```

**Compact format** (single `@pparam` with `=` separator — works because `getopt_long` natively handles `--option=value`):
```
map /path http://origin @plugin=early_hints.so @pparam=--mode=auto-learn @pparam=--max-links=15
```

Both formats are equivalent and can be mixed. The compact format is shorter but requires the t3c pparam validation fix for `--link` values containing multiple `=` signs (e.g., `as=script`).

> **Note:** For `--link` values with `as=` attributes, the compact format `@pparam=--link=<URL>;rel=preload;as=style` requires the t3c-check-refs `SplitN` fix. The standard format `@pparam=--link @pparam=<URL>;rel=preload;as=style` also requires this fix. Both work after the fix is applied.

### Options Reference

| Option | Default | Range | Description |
|--------|---------|-------|-------------|
| `--mode <modes>` | `origin-forward` | — | Comma-separated modes: `manual`, `auto-learn`, `origin-forward` |
| `--link <value>` | — | — | Manual Link header value (repeatable, **required** for `manual` mode) |
| `--max-links <n>` | `10` | 1–50 | Maximum links sent per 103 response |
| `--header-size-limit <n>` | `3072` | 256–16384 | Maximum total Link header size in bytes |
| `--min-hit-count <n>` | `2` | 1–1000 | Cache hits required before serving hints |
| `--scan-limit <n>` | `32768` | 1024–1048576 | Maximum HTML bytes to scan (auto-learn) |
| `--max-cache-entries <n>` | `10000` | 100–1000000 | Maximum entries in hints cache |
| `--skip-bots` | ON | — | Skip 103 for bot user agents |
| `--no-skip-bots` | — | — | Send 103 to all user agents including bots |
| `--navigate-only` | ON | — | Only send 103 for `Sec-Fetch-Mode: navigate` |
| `--no-navigate-only` | — | — | Send 103 for all request types |
| `--crossorigin-whitelist <domains>` | — | — | Comma-separated domains for cross-origin preloads (CORS mode) |
| `--preload-whitelist <domains>` | — | — | Comma-separated domains for cross-origin preloads (no-CORS mode) |
| `--debug-header <name>` | — | — | Add debug response header to all responses |
| `--persist-dir <path>` | ATS runtime dir | — | Custom directory for cache persistence files |
| `--no-persist` | — | — | Disable disk persistence entirely |

### Cross-Origin Resolution (Three-Tier)

When auto-learn mode scans HTML and encounters a cross-origin resource, the plugin applies a three-tier resolution:

| Priority | Config | Output | Use Case |
|----------|--------|--------|----------|
| 1 (highest) | `--crossorigin-whitelist` | `rel=preload; as=X; crossorigin=anonymous` | Fonts, ES modules (CORS fetch mode) |
| 2 | `--preload-whitelist` | `rel=preload; as=X` | Scripts, CSS, images (no-CORS fetch mode) |
| 3 (default) | Neither | `rel=preconnect` | Connection warmup only |

If a domain appears in **both** whitelists, `--crossorigin-whitelist` takes priority.

**`<link rel="modulepreload">`**: ES modules always require CORS. `--preload-whitelist` does NOT apply — use `--crossorigin-whitelist` for modules. If a module's domain is only in `--preload-whitelist`, it falls through to `rel=preconnect`.

**Fonts**: The plugin always adds `crossorigin=anonymous` for `as=font` resources regardless of which whitelist the domain is in (W3C CSS Fonts spec requirement to prevent double-fetch).

Example:
```
@pparam=--crossorigin-whitelist @pparam=fonts.googleapis.com
@pparam=--preload-whitelist @pparam=cdn.example.com,*.cdn.net
```

### Crossorigin Whitelist

By default, cross-origin resources are downgraded to `rel=preconnect` (DNS+TCP+TLS warmup only) for safety. To emit full preload hints for trusted CDN domains:

```
@pparam=--crossorigin-whitelist @pparam=cdn.example.com,fonts.googleapis.com,*.cdn.net
```

Supports exact match and wildcard prefix (`*.example.com`).
- Case-insensitive matching
- Userinfo stripped per RFC 3986 §3.2.1 (e.g., `user@cdn.example.com` → `cdn.example.com`)
- Port stripped (e.g., `cdn.example.com:443` → `cdn.example.com`)
- IPv6 literals supported (e.g., `[::1]`; port stripped after `]`)
- Leading/trailing whitespace trimmed from each domain entry

---

## Request Processing Flow

### Remap Phase (`TSRemapDoRemap`)

```
Request arrives
    │
    ├── Prior plugin error? (TSHttpTxnStatusGet ≥ 400) → skip
    ├── Method check: only GET / HEAD → others skip (TSREMAP_NO_REMAP)
    ├── Build cache key (URL path, query stripped)
    ├── Prevent duplicate hooks (first-wins if multiple instances)
    │
    ├── Protocol check: H2? ──── No ──→ skip 103 ("skipped-h1")
    │                                    ↓ but hooks still registered
    │                                    ↓ H1 clients still get Link headers in 200
    │                                    ↓ via fallback cache lookup in SEND_RESPONSE_HDR
    ├── Navigate check ────────── No ──→ skip 103 ("skipped-non-navigate")
    ├── Bot check ─────────────── Yes ─→ skip 103 ("skipped-bot")
    │
    ├── [Manual mode] → Send configured --link values as 103
    ├── [Auto/Origin mode] → Lookup cache with min_hit_count  ← Cache lookup #1
    │       ├── HIT → Send 103 with cached links ("sent")
    │       └── MISS → Skip 103 ("no-hints"), will learn this request
    │
    └── Register hooks: READ_RESPONSE_HDR, SEND_RESPONSE_HDR, TXN_CLOSE
```

**H1 client behavior in detail:** The H1 protocol check jumps directly to hook registration, skipping Cache lookup #1 and the 103 send. However, `cache_key` is already stored in per-request state before the H1 check. In `SEND_RESPONSE_HDR`, a second independent cache lookup (Cache lookup #2, with `min_hit=1`) still runs and adds Link headers to the final 200 response if the cache has entries. So H1 clients always miss the 103 Early Hint but still benefit from Link preload headers in the 200 response.

### Origin Response Phase (`READ_RESPONSE_HDR`)

```
Origin response received (200 OK only)
    │
    ├── [Origin-forward mode]
    │       ├── Extract Link headers (follows duplicate header chain)
    │       ├── Split multi-value headers (RFC 8288 comma-separated)
    │       │   Per-field limit: 8192 bytes (MAX_LINK_FIELD_LEN)
    │       ├── Validate each link via is_valid_link_value()
    │       └── cache.put() → auto-persists to disk
    │
    └── [Auto-learn mode]
            ├── Check Content-Type: text/html? → else skip
            │   (case-insensitive, allows params like "; charset=utf-8")
            ├── Check Content-Encoding: compressed? → skip
            │   (scanner needs raw HTML; "identity" encoding is allowed)
            └── Attach streaming HTML transform (passthrough — body unchanged)
                → scanner feeds same bytes for analysis
```

### Send Response Phase (`SEND_RESPONSE_HDR`)

```
Final response being sent (2xx only)
    │
    ├── Get links:
    │     ├── Manual mode → use configured links
    │     ├── Cached from remap phase (Cache lookup #1) → reuse (no double lookup)
    │     └── Fallback: Cache lookup #2 — re-query cache with min_hit=1
    │          Runs when Cache lookup #1 was not performed, which happens in two cases:
    │          (a) H1 client — remap phase skipped the lookup, but cache_key is still set;
    │              H1 clients get Link headers here even though 103 was never sent
    │          (b) First request — transform just learned hints during this request;
    │              learn_count=1 so min_hit_count check would block it in lookup #1,
    │              but min_hit=1 here allows it through for 200 compatibility
    ├── Add Link headers to 2xx response (browser compatibility)
    └── Add debug header to ALL status codes (if --debug-header configured)
```

### Debug Header Values

When `--debug-header` is set, a response header is added to **every** response:

| Value | Meaning |
|-------|---------|
| `sent` | 103 Early Hints sent successfully |
| `send-failed` | 103 send attempt failed |
| `no-hints` | No cached hints available yet (learning) |
| `skipped-h1` | Client is HTTP/1.x (103 requires HTTP/2) |
| `skipped-bot` | User agent detected as bot |
| `skipped-non-navigate` | Request is not a navigation (e.g., XHR/fetch) |
| `skipped` | Default (hooks registered but 103 not attempted) |

**Note:** Non-GET/HEAD requests are skipped via `TSREMAP_NO_REMAP` before per-request state is created, so no debug header is set for those.

---

## HTML Scanner

The auto-learn scanner is a **streaming byte-by-byte state machine** that processes the HTML `<head>` section. It is NOT a full HTML parser — it's optimized for speed and safety.

It has 10 states: `INIT` → `IN_HEAD` → `IN_TAG` / `IN_ATTR_NAME` / `IN_ATTR_SEP` / `IN_ATTR_VALUE` / `IN_COMMENT` / `IN_BOGUS_COMMENT` / `IN_SCRIPT` → `DONE`.

Key behavior: Correctly distinguishes `<head>` from `<header>` — after matching `<head`, the 6th character must be `>` or whitespace (not another alpha character).

### What It Extracts

| HTML Element | Emitted Link Header |
|---|---|
| `<link rel="preload" href="/x" as="style">` | `</x>; rel=preload; as=style` |
| `<link rel="stylesheet" href="/x">` | `</x>; rel=preload; as=style` |
| `<link rel="modulepreload" href="/x">` | `</x>; rel=modulepreload` |
| `<script src="/x">` (no async/defer) | `</x>; rel=preload; as=script` |

### What It Skips

- `<script async>` and `<script defer>` — already non-blocking
- Resources inside `<script>` / `<style>` body — raw text content
  - HTML comment sequences (`<!--`) inside `<script>` trigger a **script-escaped state** (per HTML5 spec) — text until `-->` is treated as commented-out and not scanned for tags
- Resources inside `<!-- comments -->`
- Bogus comments (`<!DOCTYPE`, `<![CDATA[`, `<?...>`) — treated as comments and skipped
- Resources after `</head>` or `<body>` — only scans `<head>`
- Non-http(s) URL schemes — scanner uses an **allowlist** (only `http:`, `https:`, and relative URLs allowed)
- Control characters, `<`/`>` in URLs, and header injection attempts
- Backslash variants in URLs (`\/`, `/\`, `\\`) treated as cross-origin per WHATWG URL spec §4.2

### Attribute Support

- `as` — **required for `rel=preload` only** (tag silently dropped if `as` is missing or has an unrecognized value). Not required for `rel=stylesheet`, `rel=modulepreload`, or `<script src>` — those have implicit fetch destinations (`style`, module, `script` respectively). Validated against known fetch destinations: `audio`, `document`, `embed`, `fetch`, `font`, `frame`, `iframe`, `image`, `object`, `script`, `style`, `track`, `video`, `worker`, `sharedworker`
- `crossorigin` — boolean or valued (`anonymous`, `use-credentials`); other values silently dropped
- `fetchpriority` — `high`, `low`, `auto` (Chrome 101+); other values silently dropped
- `type` — MIME type (sanitized, only `[a-zA-Z0-9/+.-]` characters kept); appended as quoted-string to preload results
- Fonts (`as=font`) auto-add `crossorigin=anonymous` per W3C CSS Fonts spec

### Cross-Origin Resource Handling

| Scenario | Result |
|----------|--------|
| Same-origin resource | Normal `rel=preload` |
| Cross-origin `rel=preload` + whitelisted domain | `rel=preload` with `crossorigin` |
| Cross-origin `rel=preload` + NOT whitelisted | Downgraded to `rel=preconnect` (safe: DNS/TCP/TLS only) |
| Cross-origin `rel=stylesheet` | Always `rel=preconnect` (whitelist not checked) |
| Cross-origin `rel=modulepreload` | Always `rel=preconnect` (whitelist not checked) |
| Cross-origin `<script src>` | Always `rel=preconnect` (whitelist not checked) |

**Important:** The crossorigin whitelist only applies to `<link rel="preload">`. For stylesheet, modulepreload, and script tags, cross-origin resources are always downgraded to `preconnect` regardless of the whitelist.

**Note:** All `rel=preconnect` hints for cross-origin resources include `; crossorigin=anonymous` to properly warm CORS connections.

### Limits

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_TAG_NAME_LEN` | 256 | Max tag name buffer |
| `MAX_ATTR_NAME_LEN` | 256 | Max attribute name buffer |
| `MAX_ATTR_VALUE_LEN` | 4096 | Max attribute value buffer (href, src) |

---

## Hints Cache

Thread-safe in-memory cache that stores discovered hint entries per URL path.

### Key Design

- **Cache key**: URL path with query string stripped (resources are typically identical across query variants)
- **Thread safety**: TSMutex-protected, ref-counted `shared_ptr<const vector<string>>` avoids deep copies
- **Eviction**: Oldest by `last_updated` timestamp when cache is full (note: `get()` does NOT update this timestamp — eviction is based on last write time, not last access)
- **Learn count**: Each `put()` increments `learn_count`; `get()` requires `learn_count >= min_hit_count`
- **No TTL**: Entries never expire — they live until evicted by capacity or process restart (persistence restores after restart)

### Entry Structure

```
Key:         "/path/to/page.html"
Links:       ["</style.css>; rel=preload; as=style", "</app.js>; rel=preload; as=script"]
LearnCount:  3  (updated 3 times by origin responses)
LastUpdated: 1712626800  (timestamp for oldest-write eviction)
```

---

## Disk Persistence

Cache is automatically persisted to disk and restored on restart.

### Default Behavior

- **Persistence is ON by default** (like ATS HostDB)
- File stored in ATS runtime directory (`TSRuntimeDirGet()`)
- Filename: `early_hints_{hash}.bin` where `{hash}` is FNV-1a of the remap from-URL
- Each remap rule gets its own persistence file

### Binary File Format

```
┌───────────────────────────┐
│ uint32  magic (0x45480001)│  "EH" + version 1
│ uint32  entry_count       │
├───────────────────────────┤
│ Entry 0:                  │
│   uint16  key_len         │
│   byte[]  key             │
│   uint32  learn_count     │
│   uint16  link_count      │
│   ┌─────────────────────┐ │
│   │ uint16  link_len    │ │  × link_count
│   │ byte[]  link_string │ │
│   └─────────────────────┘ │
├───────────────────────────┤
│ Entry 1: ...              │
└───────────────────────────┘
```

### Write Strategy

- **Atomic write**: Write to `.tmp` file, then `rename()` to final path
- **Triggered on every `put()`**: Each cache update persists immediately
- **Graceful shutdown**: `TSRemapDeleteInstance` also triggers `persist_to_disk()`
- **I/O outside mutex**: Snapshot data under lock, write without holding lock

### Options

| Option | Effect |
|--------|--------|
| (default) | Persist to ATS runtime dir, auto-create file |
| `--persist-dir /custom/path` | Persist to custom directory (final directory auto-created; parent dirs must exist) |
| `--no-persist` | Disable persistence entirely (in-memory only) |

**Note:** `--no-persist` takes precedence over `--persist-dir` if both are specified.

### Behavior After Restart

`last_updated` is **not stored** in the binary format. On load, all restored entries receive the current timestamp — eviction order after a restart is essentially undefined (all entries look equally "old") until subsequent writes update individual timestamps.

### Load Sanity Limits

Entries exceeding the following limits are silently skipped during load (defense against corrupt files):

| Field | Limit |
|-------|-------|
| Key length | 4096 bytes |
| Links per entry | 1000 |
| Link string length | 8192 bytes |

---

## Security Features

### Bot Detection
Skips 103 for known bot user agents (saves bandwidth):

> googlebot, bingbot, yandexbot, baiduspider, duckduckbot, slurp, ia_archiver,
> facebookexternalhit, twitterbot, linkedinbot, embedly, showyoubot, outbrain,
> pinterest, applebot, semrushbot, ahrefsbot, mj12bot, dotbot, curl/, wget/,
> python-requests/, go-http-client/, apache-httpclient/, java/, libwww-perl/

- Case-insensitive substring match
- User agents > 512 bytes treated as bot (evasion heuristic)
- Absent `User-Agent` header treated as **not bot** (conservative default — allows normal browsers that omit the header)
- Disabled with `--no-skip-bots`

### Navigate-Only Mode
Only sends 103 for browser navigation requests (`Sec-Fetch-Mode: navigate`), not XHR/fetch/subresource requests. When the `Sec-Fetch-Mode` header is **absent** (older browsers, curl), the request is treated as navigate and **allowed** through. Disabled with `--no-navigate-only`.

### Link Header Validation
Every Link header value (from `--link` config and origin-forwarded headers) is validated via `is_valid_link_value()` before sending:
- Must have `<url>` delimiters
- No control characters or DEL
- No nested `<` / `>` (prevents header injection)
- Blocked URL schemes (denylist): `javascript:`, `data:`, `vbscript:`, `blob:`
- Must have valid `rel=` value: `preload`, `preconnect`, `stylesheet`, `modulepreload`
- Supports unquoted (`rel=preload`), double-quoted (`rel="preload"`), and single-quoted (`rel='preload'`) variants

**Note:** The HTML scanner uses a stricter **allowlist** approach — only `http:`, `https:`, and relative URLs are permitted. All other schemes are rejected regardless.

### Cache Key Normalization
Query strings are stripped to prevent cache pollution attacks (attacker appending random `?rand=N` to create unlimited keys). An empty path (e.g., a request to `https://example.com` with no path) is normalized to `/`.

### First-Wins Instance Check
ATS can apply multiple remap rules to a single transaction (e.g., chained remaps or overlapping rule patterns), and each matching rule may have early_hints attached. Without protection, one request could trigger multiple instances — resulting in duplicate 103 responses and conflicting configurations.

The plugin uses a global per-transaction slot (`TSUserArgSet`) to claim ownership. When the first instance runs, it stores its `RequestData` in that slot. Every subsequent instance checks the slot first: if it is already occupied, that instance skips immediately (`TSREMAP_NO_REMAP`). This means:

- The **first matching remap rule** wins and processes the transaction completely
- Subsequent early_hints instances on the same transaction are silently bypassed
- **Different requests** are fully independent — each transaction has its own slot, so separate requests each pick up their own matching rule normally

---

## Statistics

Registered under `plugin.early_hints.*`:

| Stat Name | Description |
|-----------|-------------|
| `103_sent` | Count of 103 Early Hints responses sent |
| `103_skipped_h1` | Skipped: client is HTTP/1.x |
| `103_skipped_bot` | Skipped: bot user agent detected |
| `103_skipped_no_hints` | Skipped: no cached hints available |
| `103_skipped_non_nav` | Skipped: non-navigate Sec-Fetch-Mode |
| `hints_learned` | New hints learned from origin responses |

View with: `traffic_ctl metric match early_hints`

---

## Examples

### Basic Auto-Learn

```
# Standard format
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode @pparam=auto-learn \
    @pparam=--debug-header @pparam=X-Early-Hints

# Compact format (equivalent)
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=auto-learn \
    @pparam=--debug-header=X-Early-Hints
```

### Manual Mode with Specific Resources

```
# Standard format
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode @pparam=manual \
    @pparam=--link @pparam=</critical.css>;rel=preload;as=style \
    @pparam=--link @pparam=</app.js>;rel=preload;as=script

# Compact format (equivalent)
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=manual \
    @pparam=--link=</critical.css>;rel=preload;as=style \
    @pparam=--link=</app.js>;rel=preload;as=script
```

### Combined Auto-Learn + Origin Forward with CDN Whitelist

```
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=auto-learn,origin-forward \
    @pparam=--crossorigin-whitelist=cdn.example.com,fonts.googleapis.com \
    @pparam=--min-hit-count=3 \
    @pparam=--max-links=15
```

### High-Traffic with Tuned Cache

```
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=auto-learn \
    @pparam=--max-cache-entries=50000 \
    @pparam=--min-hit-count=5 \
    @pparam=--scan-limit=65536
```

### Disable Persistence (Ephemeral Cache)

```
map https://www.example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=auto-learn \
    @pparam=--no-persist
```
