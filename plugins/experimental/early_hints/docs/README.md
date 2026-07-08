# ATS Early Hints Plugin

## Overview

The Early Hints plugin enables Apache Traffic Server to send HTTP 103 Early Hints responses to HTTP/2 clients before the origin server finishes processing the full HTML response. 

This allows browsers to start downloading critical assets like CSS files, JavaScript, and Web Fonts earlier. The result is significantly faster page load times.

The plugin automatically handles HTTP/1.x clients by skipping the 103 response since it is not supported in the spec. For the final 200 OK response, Link headers are injected only if HTTP/2 traffic has already warmed the URL's `request_count` past `min-hit-count`. If a site receives exclusively HTTP/1.x traffic and no HTTP/2 clients have warmed the URL, Link headers will NOT be injected into 200 OK responses for auto-learn and origin-forward modes. For `manual` mode, Link headers bypass the `min-hit-count` threshold entirely and are always injected into the 200 OK for all HTTP versions.

## Operating Modes

You can choose one of three ways to tell the plugin which assets to hint. These modes can also be combined.

### 1. manual
How it works: You hardcode the asset URLs directly in your remap.config.
When to use it: Best for global assets that exist on every page and rarely change, such as a global stylesheet or vendor script.

### 2. auto-learn
How it works: The plugin attaches an HTML scanner transform that scans the head section of the response body as it streams from the origin. It finds `link rel="preload"`, `link rel="stylesheet"` (converted to `rel="preload"; as="style"` in the output), `link rel="modulepreload"`, `<script src="...">` and `<script type="module">` tags, then saves them to memory. 
Scanner Limitations:
* Classic `<script>` tags with `async` or `defer` attributes are skipped. For `<script type="module">`, only `async` is skipped (because ES modules are implicitly deferred by the HTML spec).
* The scanner does not begin collecting hints until it detects a `<head` opening tag (case-insensitive). HTML documents without a `<head>` section (e.g., HTML fragments or non-standard documents) will produce no hints.
* The scanner stops automatically if it sees a `</head>` closing tag or an opening `<body>` tag.
* The scanner enters a raw text mode and completely ignores any hints located inside `<noscript>`, `<template>`, `<title>`, `<textarea>`, `<xmp>`, `<style>`, and `<script>` tags.
* Script Escaped State: when `<!--` appears inside a `<script>` block, the scanner enters HTML5 spec §13.2.6.2 "script data escaped" mode. In this mode, `</script>` does NOT close the script block  -- only `-->` exits escaped mode, allowing the next `</script>` to close normally. This prevents the scanner from being confused by JavaScript strings containing HTML-like tokens.
* The scanner correctly handles HTML5 bogus comments (`<!DOCTYPE html>`, `<![CDATA[...]]>`) by skipping their content without corrupting the parser state.
* If any attribute inside a tag exceeds 4096 bytes (e.g., a massive `integrity` hash or base64 inline data), the scanner silently discards the entire tag.
* If a quoted attribute value (e.g., `href="..."`) hits the end-of-file or the scan limit before the closing quote is found, the scanner silently discards the entire tag because it never exits the value parsing state to trigger the tag processing logic.
* Explicit `<link rel="preconnect">` tags written in your HTML are NOT learned. Preconnects in this plugin are only generated as a downgrade mechanism for non-whitelisted cross-origin resources.
* The scanner only runs if the origin sends `Content-Type: text/html` and the body is NOT compressed (i.e., `Content-Encoding` must be `identity` or absent). If your origin sends gzipped HTML, the scanner will silently skip it.
* URL scheme enforcement: the scanner rejects any `href` that uses a scheme other than `http://`, `https://`, or a relative path. `data:`, `javascript:`, `blob:`, and all other exotic schemes are silently dropped. Backslash-based authority references (`\\evil.com`, `/\path`) are also rejected.
When to use it: Highly recommended for dynamic websites where assets change frequently, like Webpack builds with hashes in the filenames.

### 3. origin-forward
How it works: The plugin reads Link headers directly from the 200 OK response sent by your origin server. It normalizes them, caches them, and forwards them as 103 responses on subsequent requests. Note on Limits: If the origin server returns a single `Link` header field that exceeds 8192 bytes (`MAX_LINK_FIELD_LEN`), the plugin silently ignores that entire header field.
Normalization Rule: `rel=stylesheet` is the only relation type that receives a structural conversion. The reason is that `rel=stylesheet` is a registered IANA HTTP Link relation type (so backends commonly send it in HTTP headers) but browsers do **not** speculatively fetch stylesheets triggered by a 103 response with `rel=stylesheet` -- browsers only act on `rel=preload`, `rel=preconnect`, and `rel=modulepreload` inside a 103. All other types the plugin handles (`preload`, `preconnect`, `modulepreload`) are already correct for 103 and pass through unchanged. A structural rebuild would risk silently dropping custom attributes (`integrity=`, `nonce=`, `media=`, `type=`, etc.) that the origin intentionally included and that the browser requires. Therefore those types are forwarded verbatim. Only `rel=stylesheet`, which has no valid 103 representation without conversion, is rebuilt into `rel=preload; as=style`. During this specific conversion the plugin also explicitly preserves `crossorigin` and `fetchpriority` attributes if present. For the stylesheet conversion, attribute values are **lowercased** during extraction (e.g., `crossorigin="Anonymous"` becomes `crossorigin="anonymous"`). Bare boolean `crossorigin` attributes (i.e., the word `crossorigin` without a `=value`) are normalized to `crossorigin=anonymous`, per the HTML spec (section 2.5.3). For `fetchpriority`, only the three spec-defined tokens `high`, `low`, and `auto` are forwarded; any other value is silently dropped as a security measure.

IMPORTANT: Lowercasing and bare `crossorigin` normalization apply **only during the stylesheet-to-preload conversion**. Links with `rel=preload`, `rel=preconnect`, and `rel=modulepreload` pass through the normalization step **unchanged** -- their attribute values, including `crossorigin=Anonymous`, are forwarded exactly as the origin sent them.
The plugin drops unsupported relationships completely (such as `rel=prefetch` or `rel=dns-prefetch`). Other supported tags (`preload`, `preconnect`, and `modulepreload`) pass through the normalization step unchanged. Note: unlike auto-learn which ignores `<link rel="preconnect">` tags in HTML, origin-forward *does* forward `rel=preconnect` headers from the origin unchanged. A separate validation step immediately follows: if a `rel=preload` tag lacks a valid `as=` attribute, the plugin silently drops it. (`rel=modulepreload` is an exception and does not require `as=` because the HTML spec defaults its destination to "script"). The validation step also rejects any Link header value that contains `<` or `>` characters in the params portion (after the closing `>` of the URL), preventing injection of additional link-values via malformed attribute values. As a further security measure, the validation step rejects backslash-based authority references (`\\evil.com`, `\/evil.com`, `/\evil.com`) and any URL scheme other than `http://`, `https://`, or relative URLs. This prevents SSRF via origin-forwarded Link headers from a compromised or misconfigured origin.
Cross-Origin Whitelist Behaviour: The `--crossorigin-whitelist` and `--preload-whitelist` options only affect the **auto-learn scanner**. In origin-forward mode the plugin treats the origin as the authoritative source for CORS decisions. If the origin sends `crossorigin=anonymous` on a Link header, the plugin forwards it unchanged. The whitelist-based downgrade from `rel=preload` to `rel=preconnect` for non-whitelisted cross-origin resources does **not** apply to origin-forward. This is intentional: the origin has already made the correct CORS determination for its own Link headers. Operators running combined mode (`--mode=auto-learn,origin-forward`) should be aware that auto-learned hints respect the whitelist while origin-forwarded hints do not.
TTL Refresh: When a hints entry is stale (age > `--hints-ttl`) but the ATS cache is still fresh (READ_CACHE_HDR fires instead of READ_RESPONSE_HDR), the plugin calls `touch()` to reset the entry's timestamp without modifying the stored links. This mirrors auto-learn stale behaviour. The safety argument is: if the origin had changed its Link headers, it would have changed the HTML body too, causing the ATS cache to expire and triggering READ_RESPONSE_HDR with fresh headers. An ATS cache hit with a stale hints entry therefore means the stored links are still valid.
When to use it: Use this if your backend application already generates Link headers automatically.

## Usage Examples

### 1. Origin Forward Mode (Default)
Forwards Link headers from the origin.
```text
map https://example.com https://origin.example.com \
    @plugin=early_hints.so
```

### 2. Manual Mode
Defines assets statically.
```text
map https://example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=manual \
    @pparam=--link="</css/main.css>; rel=preload; as=style" \
    @pparam=--link="</js/app.js>; rel=preload; as=script"
```

### 3. Auto Learn Mode
Learns HTML automatically, saves it to disk for persistence, and only sends 103 if a page has been accessed at least 3 times.
```text
map https://example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=auto-learn \
    @pparam=--persist-dir=/var/run/trafficserver/early_hints \
    @pparam=--min-hit-count=3 \
    @pparam=--crossorigin-whitelist="cdn.example.com"
```

### 4. Advanced Setup (Cache TTL, Stale Eviction, and Purge)
Uses Auto Learn with a 1-week TTL. Stale entries are evicted after 2 days of
inactivity. Purges are accepted only up to 3 times per 60-second window.
```text
map https://example.com https://origin.example.com \
    @plugin=early_hints.so \
    @pparam=--mode=auto-learn \
    @pparam=--hints-ttl=604800 \
    @pparam=--stale-evict-after=172800 \
    @pparam=--purge-header=X-Hints-Purge \
    @pparam=--purge-secret=deploy_secret_123 \
    @pparam=--purge-limit=3 \
    @pparam=--purge-cooldown=60
```
To clear the cache for the /home page during a deploy:
`curl -H "X-Hints-Purge: deploy_secret_123" https://example.com/home`

## Configuration Reference

All options use the syntax `@pparam=--option=value`. Because the plugin uses `getopt_long` internally, the equivalent space-separated form `@pparam=--option @pparam=value` also works and is used in the gold tests.

### Basic Settings
* `--mode`: Can be `manual`, `auto-learn`, or `origin-forward`. You can combine them with commas. Default is `origin-forward`. Note that if you set `--mode=manual` but do not provide at least one `--link` parameter, the ATS remap rule will fail to load and throw a `TSError`.
* `--link`: Static link for manual mode. Can be used multiple times. No default. Note on Validation: If a manual link fails fundamental structural validation (`is_valid_link_value()` returns false), the ATS remap rule will throw a `TSError` and fail to load. Warning: If the link is structurally valid but simply lacks an `as=` attribute (for `rel=preload`), the plugin logs a warning using the `TSError` macro (meaning it appears in the ATS logs at the ERROR level) but will still inject it. This differs from `origin-forward` mode, which silently drops invalid preloads. Note on `rel=stylesheet`: manually specifying `rel=stylesheet` is normalized to `rel=preload; as=style` at config-parse time by `normalize_link_for_hint()`, matching the same conversion applied in origin-forward and auto-learn modes. The normalized form is what gets stored and sent.
* `--max-links`: Maximum number of Link headers sent in a single 103 response. Range: 1 to 50. Default is 10.
* `--header-size-limit`: Total byte size limit for Link headers to prevent header overflow. Each Link header incurs an 8-byte framing overhead (`Link: ` = 6 bytes + `\r\n` = 2 bytes) in addition to the value's own byte length. If adding a link would exceed this limit, the plugin skips that specific link and continues evaluating the remaining links (the smallest-first selection allows multiple small links to fit even if one oversized link would exceed the budget). Note that this limit applies to both the 103 Early Hints response AND the final 200 OK response. Range: 256 to 16384. Default is 3072.
* `--debug-header`: Adds a custom response header showing the internal status of the early hints decision. The provided name is strictly validated as an RFC 7230 token (if invalid, the ATS remap rule will fail to load). Possible values: `sent`, `send-failed`, `skipped-bot`, `skipped-h1`, `skipped-non-navigate`, and `no-hints`. Note that this header is attached to the HTTP response ONLY if the request passes the initial remap checks (i.e., it must be a GET/HEAD request and not already rejected by a prior plugin). If the request is rejected early, the hooks are never registered and this header will not appear, even on 4xx/5xx responses. Note: the debug header is attached to ALL response status codes (not just 200 OK), so it appears on redirects, 404s, 500s, etc., which is useful for debugging plugin behavior on error pages. Default is disabled.

### Traffic Filtering
* `--skip-bots`: Blocks sending 103 to bots based on the User Agent. This uses case-insensitive matching (`strcasestr`) against a hardcoded list of 26 substrings: `googlebot`, `bingbot`, `yandexbot`, `baiduspider`, `duckduckbot`, `slurp`, `ia_archiver`, `facebookexternalhit`, `twitterbot`, `linkedinbot`, `embedly`, `showyoubot`, `outbrain`, `pinterest`, `applebot`, `semrushbot`, `ahrefsbot`, `mj12bot`, `dotbot`, `curl/`, `wget/`, `python-requests/`, `go-http-client/`, `apache-httpclient/`, `java/`, `libwww-perl/`. Additionally, as a security feature, any User-Agent string longer than 512 bytes is automatically classified as a bot. Note: if the `User-Agent` header is completely absent from the request, the client is conservatively treated as NOT a bot (i.e., unknown clients are not blocked). Default is ON. Use `--no-skip-bots` to disable.
* `--navigate-only`: Only sends 103 for browser navigation requests based on the Sec-Fetch-Mode header. Note that if the header is completely absent (e.g., older browsers that predate Fetch Metadata support, or non-browser clients that do not send this header), the plugin treats it as a valid navigate request. Default is ON. Use `--no-navigate-only` to disable.

### Auto Learn and Memory Cache
* `--scan-limit`: The maximum bytes of HTML from the top of the page that will be scanned. Range: 1024 to 1048576 (1MB). Default is 32768.
* `--min-hit-count`: The number of requests a URL needs before ATS starts serving 103 responses for it. Range: 1 to 1000. Default is 2.
* `--max-cache-entries`: Maximum number of URLs stored in the LRU Memory Cache. Range: 1 to 1000000. Default is 10000. Note: The plugin strips the query string when generating the cache key. This means `/page?version=1` and `/page?version=2` share the exact same hints cache entry. URL path comparison is **case-sensitive** (per RFC 3986 §6.2.2.1): `/Page.html` and `/page.html` are treated as different cache entries. Only the URL scheme and hostname are lowercased for case-insensitive matching.

### Security and Whitelists
* `--crossorigin-whitelist`: A comma-separated list of allowed domains for full cross-origin `rel=preload` with `crossorigin=anonymous`. Cross-origin resources from domains NOT on this list (and not on `preload-whitelist`) are downgraded to `rel=preconnect` to save bandwidth. Note that the plugin silently strips ports during parsing (e.g., `domain.com:443` becomes `domain.com`). The scanner limits total link hint injections based on the `--max-links` setting (default 10). Wildcards are supported for ANY subdomain depth because it uses a pure suffix match (e.g., `*.domain.com` matches `foo.domain.com`, `bar.foo.domain.com`, and `attacker.evil.domain.com`). Default is empty (disabled).
* `--preload-whitelist`: A comma-separated list of allowed domains for no-cors `<script>` and `rel=stylesheet` cross-origin preloads (it injects `rel=preload` but strips the `crossorigin` attribute). Like `--crossorigin-whitelist`, wildcards are supported for ANY subdomain depth (pure suffix match). Default is empty.
  > **⚠️ Warning for module scripts (`rel=modulepreload` and `<script type="module">`):** placing their domain in `preload-whitelist` strips the `crossorigin` attribute, producing a no-cors preload. However, ES modules are **always** CORS-fetched by the browser (HTML spec §8.1.4.2). A no-cors preload and a CORS actual-fetch are cached separately, so the preload will be ignored and the browser will perform a **second (CORS) fetch** for the same file. To avoid this double-fetch for module scripts, use `--crossorigin-whitelist` instead, which preserves `crossorigin=anonymous`.

**Whitelist Mode Summary:**
| Whitelist Match | Fetch Type | Output Link Header |
|-----------------|------------|--------------------|
| `--crossorigin-whitelist` | CORS | `rel=preload; as=X; crossorigin=anonymous` |
| `--preload-whitelist` | no-cors | `rel=preload; as=X` (no crossorigin) |
| Neither | N/A | Downgraded to `rel=preconnect` |

### Disk Persistence
* `--persist-dir`: Directory path for storage. If the directory does not exist, it is automatically created with 0750 permissions. Highly recommended so the cache survives an ATS restart. The temporary (`.tmp`) and final binary cache files (`.bin`) are created inside this directory with `0640` permissions (owner read-write, group read-only). The actual filename is generated using a 64-bit FNV-1a hash of the from-URL (the source URL) of the remap rule (e.g., `early_hints_a1b2c3d4e5f6a7b8.bin`). If this option is enabled but provided with an empty value, the plugin automatically falls back to the ATS Runtime Directory (`TSRuntimeDirGet()`). Default is disabled.
* `--no-persist`: Explicitly disables persistence, overriding `--persist-dir`.
* `--persist-throttle`: Interval in seconds between disk writes to prevent excessive disk I/O during high traffic. Note that this is a synchronous time-comparison check, not an asynchronous timer thread. It governs all disk operations, meaning disk flushes triggered by `touch()` (TTL refreshes) and `remove()` (purges) are also subject to this interval. Range: 0 to 300. Default is 10.

### TTL and Invalidation
* `--hints-ttl`: Time in seconds before a cache entry is considered stale and the HTML scanner reattaches to relearn hints. Range: 0 to 31536000 (1 year). Default is 604800 (1 week). Set to 0 to disable TTL entirely (entries live until LRU eviction or manual purge).
* `--stale-evict-after`: Grace period in seconds after an entry becomes stale before it is permanently evicted. The eviction threshold is computed as `hints_ttl + stale_evict_after`. An entry is served normally throughout the stale grace window (age >= hints_ttl but age < hints_ttl + stale_evict_after). Only when `age > hints_ttl + stale_evict_after` (strictly greater than) does the entry get served one final time and then removed  -- the next request triggers re-learning. An entry at exactly `age == hints_ttl + stale_evict_after` is NOT yet evicted; it survives for one more second. If `hints_ttl` is 0 (disabled) or `stale_evict_after` is 0, the combined eviction is disabled entirely (entries are kept for Stale While Revalidate and only replaced by a new `put()`). Note: Stale-While-Revalidate re-learns during the grace window reset the entry's `last_updated` timestamp, effectively extending the entry's life. Eviction only happens if the entry was NOT refreshed within the combined threshold (e.g., origin no longer returns preloadable links). Range: 0 to 31536000. Default is 0 (disabled).
* `--purge-header`: The HTTP header name used to trigger a cache purge for a specific URL. Like `--debug-header`, the provided name is strictly validated as an RFC 7230 token (if invalid, the ATS remap rule will fail to load). Default is disabled.
* `--purge-secret`: A secret token required to authorize purges. Note: `--purge-header` and `--purge-secret` MUST be used together; configuring one without the other will cause the ATS remap rule to fail to load. If configured, you can send an HTTP request containing your configured purge header with this secret token as its value to explicitly delete the cached hints for that URL. Note that if the purge header is present but the token is missing or incorrect, the plugin silently ignores the purge attempt and processes the request normally (no 403 Forbidden is thrown).
* `--purge-limit`: Maximum number of successful purges allowed within a single `--purge-cooldown` window per remap rule. Excess purge attempts within the same window are rejected: the cache is NOT invalidated and a note is logged to diags.log via `TSNote`. Range: 1 to 500. Default is 3. Has no effect unless `--purge-header` is also set.
* `--purge-cooldown`: Duration in seconds of the rate-limit window for purge requests. After the window expires, the counter resets and purges are allowed again up to `--purge-limit`. Range: 1 to 2592000 (1 month). Default is 10. Has no effect unless `--purge-header` is also set.

## Request Processing Flow

Note on Multiple Rules: If multiple remap rules match and use `early_hints.so`, only the first instance processes the transaction. Subsequent instances are silently skipped.

#### First Request (Cache Miss)
1. `TSRemapDoRemap`: The plugin checks the cache. Because the entry does not exist in the cache (the `get()` call returns immediately), no `request_count` is incremented. Because the request does not meet the `min-hit-count` threshold, the plugin skips sending the 103 response. It then registers the `READ_RESPONSE_HDR` hook to process the future response.
2. `TS_HTTP_READ_RESPONSE_HDR_HOOK`: ATS receives the response from the origin. **The plugin only processes 200 OK responses**. Non-200 responses (redirects, 4xx, 5xx, 206 partial content, etc.) are silently skipped, no learning or scanning occurs. At this stage, the plugin performs two setup tasks depending on the mode:
   * **auto-learn**: Creates and attaches the HTML scanner transform to read the upcoming response body.
   * **origin-forward**: Extracts and normalizes the `Link` headers directly from the origin's response. This extraction is **skipped** if hints are already learned and fresh (i.e., `has_learned=true` and `needs_relearn=false`) to avoid redundant header parsing on cached entries.
3. The extracted links are saved to memory via `cache->put()`. (Note: It is at this moment that the entry is created in memory, and its `request_count` defaults to `0` via C++ initialization).
4. `TS_HTTP_SEND_RESPONSE_HDR_HOOK`: Because the `request_count` is 0 (which is below the default `min-hit-count` of 2), the plugin does **NOT** inject any links into the 200 OK response. The very first request receives neither a 103 nor 200 OK Link headers. Note: Link headers are only injected into 200 OK responses. Partial (206), no-content (204), redirects (3xx), and error (4xx/5xx) responses are skipped because they do not correspond to a loadable document, adding preload hints to them would cause spurious fetches in the browser.

### Subsequent Requests
1. TSRemapDoRemap: The plugin checks the cache. It increments the `request_count`. If it meets the `min-hit-count` (or if mode is `manual`), it immediately sends a 103 response to the browser.
2. READ_RESPONSE_HDR or READ_CACHE_HDR: 
   * **Normal Origin Response (Scanner Bypass)**: The scanner is bypassed if `has_learned=true` (entry exists in the hints cache) AND `needs_relearn=false` (TTL not expired). This guard applies to ALL origin responses  -- including responses where `Cache-Control: no-cache` or `no-store` prevents ATS from caching the HTTP body. Specifically: for a no-cache origin, the first request runs the scanner and saves hints to RAM. All subsequent requests have `has_learned=true`, so the scanner is skipped even though ATS must re-fetch from origin every time. The scanner only re-runs when `hints_ttl` expires and sets `needs_relearn=true`. This makes auto-learn very efficient for no-cache sites: the HTML is scanned once per TTL cycle, not on every request.
   * **ATS Cache Hit Self-Healing**: ATS caches the 200 OK body from the origin. If the Early Hints plugin's memory cache is cleared (e.g., via LRU eviction), the plugin loses the hint URLs. Because ATS serves the cached 200 OK body directly, the normal origin hook (`READ_RESPONSE_HDR`) is never triggered, leaving the plugin permanently blind to those hints until the ATS disk cache expires. To fix this, the plugin attaches a hook to `READ_CACHE_HDR`:
     * **Auto-Learn**: The HTML scanner attaches directly to the ATS cached response body to learn hints without contacting the origin. In addition, `READ_CACHE_HDR` calls `get()` to increment `request_count` for any client whose `cached_links` is still null at this point in the transaction  -- this covers H1 clients (which do not call `get()` at remap time) AND H2 clients whose `get()` at remap returned null (e.g., entry existed but was below `min-hit-count`). Without this, ATS cache hits for these clients would never reach `min-hit-count` and Link headers would never be injected into the 200 OK response.
     * **Origin-Forward**: The plugin reads the `Link` headers stored inside the ATS cached response and uses them to self-heal the memory cache. Note: Self-healing only runs when the entry is completely absent from the memory cache (`!req_data->cached_links && !req_data->has_learned`). If the entry exists but its `request_count` is below `min-hit-count` (a "warming up" phase), self-healing is deliberately skipped to avoid overwriting existing in-progress entries.
3. SEND_RESPONSE_HDR: Link headers are injected into the 200 OK response if the `request_count` threshold is met.
   * **Symmetric Timing**: The 103 Early Hints response and the Link headers in the 200 OK response are injected starting from the **same request**. There is no longer an asymmetric double-get. With `min-hit-count=2`:

     | Request | `request_count` in Remap | 103 Sent? | Link in 200 OK? |
     |---------|--------------------------|-----------|------------------|
     | #1 | miss → `put()` → `request_count = 0` | No | No |
     | #2 | 0→1 (< 2) | No | No |
     | #3 | 1→2 (≥ 2) → `cached_links` set | **Yes** | **Yes** |

     For the 200 OK Link injection on requests where `cached_links` is not yet set (e.g., H1 clients, or first request after ATS restart), `SEND_RESPONSE_HDR` uses a non-incrementing `peek()` + `get_count()` fallback to check if the threshold has been met before serving.

### Conditions for Sending 103
ATS only sends a 103 response if all of these are true:
1. Client connects via HTTP/2. (Note: HTTP/3 is not currently supported. Any HTTP/3 request fails the `"h2"` string check and receives the exact same `skipped-h1` treatment as an HTTP/1.x client).
2. Request method is GET or HEAD. (Note: Non-GET/HEAD requests such as POST and PUT completely bypass the plugin  -- no hooks are registered, no learning occurs, and the `--debug-header` is never attached to those responses.)
3. The client is not a Bot.
4. The request is a page navigation.
5. The merged list of link headers is not empty.
6. The request has not already been marked with an error status (e.g., 403 Forbidden) by a previous ATS plugin in the remap chain.
Note: If you use a combined mode (e.g., `manual,auto-learn`), the `min-hit-count` threshold still applies to the auto-learned links, but the `manual` links completely bypass the threshold and are sent immediately on the first request if the above conditions are met. (Individual links may still be silently dropped if appending them exceeds `--header-size-limit`).

## Deep Dive

### The Hints Cache Internals

Traffic Gate & Key Limits:
Each cache entry tracks a `request_count` (the traffic gate). This is the only counter used by the plugin to make serving decisions. Note on `put()` efficiency: the plugin includes an equality-check debounce. Repeatedly calling `put()` with identical links skips heap allocation, though it still updates the `last_updated` timestamp and marks the cache as dirty to trigger disk persistence. The decision to bypass the scanner on subsequent requests is based strictly on a `has_learned` flag (whether the URL exists in the cache at all). Disk persistence is triggered strictly by an internal `is_dirty` flag and governed by the `persist-throttle` interval check. Note that any URL (cache key) exceeding 4096 bytes is silently dropped by the cache and will never be learned.

Probabilistic LRU:
To reduce lock contention on highly trafficked sites, the cache updates its LRU (Least Recently Used) order probabilistically using a global cache access counter. An entry is promoted to the top of the LRU list only 1 out of every 16 total accesses across the entire cache. The counter is shared globally across all entries (not per-entry), so LRU eviction is approximate, not exact.

The peek vs get Methods:
* `get`: Increments `request_count` and returns links only if `min-hit-count` is met.
* `peek`: Returns links if they exist, without checking `min-hit-count` and without incrementing `request_count`.

*(Note on `debug_status`: the plugin initially sets `req_data->debug_status = "skipped"` when a request begins. For all valid GET/HEAD requests that pass the early remap checks, this value is always overwritten by one of the six valid values. Non-GET/HEAD requests completely bypass the plugin  -- no `req_data` is allocated and no `debug_status` is ever written for them).*

Example Case:
A Googlebot crawls your site (or a client uses HTTP/1.x, or it's a non-navigate request). ATS skips sending the 103 response. However, before exiting the remap phase, ATS still uses `peek` to check the cache. If it finds the URL is already learned, it sets `has_learned=true`. When the HTML arrives later in the transaction, ATS skips the CPU heavy HTML scanner. If ATS had used `get` instead of `peek` for these skipped requests, the traffic would have artificially inflated the `request_count`, potentially triggering Early Hints for real users prematurely.

Immutable Link Storage:
Cached links are wrapped in a `shared_ptr` to a `const vector`. This guarantees thread safety without deep copying memory. Multiple request threads can read the same vector simultaneously.

### Cross Origin Handling Detail

The scanner automatically categorizes external URLs and applies CORS rules. 

Example Case: 
Your HTML contains `<link rel="preload" as="style" href="https://cdn.example.com/style.css">`.
1. If `cdn.example.com` is in `crossorigin-whitelist`: Output is `<https://cdn.example.com/style.css>; rel=preload; as=style; crossorigin=anonymous`. The browser preloads the file securely.
2. If `cdn.example.com` is NOT whitelisted: Output is downgraded to `rel=preconnect`. The URL is aggressively truncated to just the origin (scheme + host), resulting in `<https://cdn.example.com>; rel=preconnect`. The `as=style` and `crossorigin=anonymous` attributes are cleared because they are not valid on preconnects for non-font resources. This safely warms up the TLS connection without wasting bandwidth downloading an unauthorized file, and collapses multiple links to the same domain into a single hint.

The W3C Font Specification Exception:
The W3C specification strictly requires that all Web Fonts (`.woff`, `.woff2`, `.ttf`, etc.) must be fetched using anonymous CORS, even if they are hosted on the same origin as the HTML.
Because of this, if the HTML scanner detects a `<link rel="preload" as="font">`, the plugin intercepts this and forces `crossorigin=anonymous`, unless the domain is in `--preload-whitelist` which overrides this and strips the attribute entirely.
Additionally, if a cross-origin font is downgraded to `preconnect` (non-whitelisted domain), the plugin retains `crossorigin=anonymous` on the `preconnect` hint. This is because fonts are always CORS-fetched, so the preconnect must establish a CORS-capable connection for the browser to reuse it during the subsequent `@font-face` fetch. Without `crossorigin`, the browser would open a separate CORS connection, negating the preconnect benefit.

The Module Script Exception:
Unlike stylesheets, module scripts (`rel="modulepreload"` or `<script type="module">`) are explicitly required by the HTML spec to use CORS. Therefore, if a cross-origin module script is downgraded to `preconnect`, the plugin WILL forcefully retain `crossorigin=anonymous` on the `preconnect` hint.

### Deduplication Layers

The plugin prevents sending duplicate Link headers through a 3 layer check.

1. **Scanner Internal**: URL-only, strongest-wins. If two tags resolve to the same URL, the stronger rel type wins: `preload`/`modulepreload` takes priority over `preconnect`. This resolves the case where the same cross-origin domain appears both as a whitelisted preload and as a preconnect downgrade.
2. **Origin Forward Internal**: Same URL-only strongest-wins logic as the scanner. Deduplication runs **once** after all `Link` header fields have been collected from the origin response, not per field. This ensures correct strongest-wins decisions across multi-field headers (e.g., a `rel=preconnect` in field 1 and `rel=preload` for the same URL in field 2 correctly resolves to `rel=preload`).
3. **Merge Phase**: Combines manual links and cached links. Compares URL only. `preload` and `modulepreload` subsume `preconnect` for the same URL.

Merge Phase Operator Override Behavior:
Because the Merge phase always prefers manual links over cached links (URL dedup, first-seen wins), a manual link always overrides the same URL learned by the scanner or origin-forward. This is intentional  -- manual mode represents explicit operator intent and has absolute priority. For example, if you configure `--link="<https://cdn.com/app.js>; rel=preconnect"` and the auto-learn scanner also finds `rel=preload` for that same URL, the cached preload is dropped. Your manual `preconnect` wins. If this is not the desired behavior, simply remove the URL from the `--link` list and let the scanner or origin-forward serve it.

### Purge Mechanism

Unlike standard cache clearing which can be slow, this plugin purges in O(1) time complexity using a hash map lookup.

Example Case & ATS Cache Interaction:
You deploy an update for the `/about` page. You send a purge request specifically to `https://example.com/about`. The plugin instantly deletes the hints for `/about` from RAM. Crucially, the plugin **only** clears the Early Hints cache, not the ATS HTTP cache. 
* If your purge request is served from the ATS HTTP cache, the plugin will simply rescan the old HTML and relearn the old hints (Auto-Learn) or leave the hints empty until a real origin miss occurs (Origin-Forward).
* To truly fetch the updated HTML and relearn the new hints immediately, your purge request must also bypass the ATS HTTP cache (e.g., via `curl -H "X-EH-Purge: secret" -H "Cache-Control: no-cache"`, assuming ATS is configured to honor client no-cache). The purging request itself will then trigger the scanner on the new origin response, and the very next user will receive the updated 103 Early Hints.

Secret Verification: The `purge-secret` is compared using `constant_time_eq`, a constant-time byte comparison that processes `max(a_len, b_len)` bytes regardless of length mismatch. Length differences are folded into the XOR accumulator rather than handled by an early return, eliminating timing differences that could leak the secret length to an attacker.

Rate Limiting:
To prevent a client with the purge secret from repeatedly invalidating hints faster than the scanner can relearn them, the plugin enforces a per-remap fixed-window rate limit via the `PurgeRateLimiter` struct stored in `PluginInstance`.

* The limiter is only created when `--purge-header` is set (zero overhead otherwise).
* On each valid purge request (correct secret), `allow()` is called. If the call count within the current window exceeds `--purge-limit`, the purge is rejected: `cache->remove()` is skipped, a `TSNote` is written to diags.log (visible without debug mode enabled), and the `plugin.early_hints.purge_rate_limited` stat is incremented.
* The current request still returns 200 OK normally; only the cache invalidation is suppressed.
* The window resets after `--purge-cooldown` seconds. The window reset uses a compare-and-swap (CAS) operation so that exactly one thread wins the reset when multiple threads call `allow()` at the window boundary simultaneously. Without CAS, a TOCTOU race would allow all racing threads to reset the counter independently, letting up to `N * limit` purges through in a single window.

### TTL and Stale While Revalidate

If you configure `hints-ttl`, the plugin evaluates the entry's age. Note that `HintsCache::get()` itself does not check the TTL. Instead, after a successful `get()` in the remap phase, the plugin explicitly calls `cache->get_age()` to calculate the staleness.

Example Case (Origin Response):
Your cache TTL expires. A user requests the page. The plugin still sends the old, stale 103 response instantly so the user does not have to wait (Stale While Revalidate). Transparently, as the response body streams from the origin, it reattaches the HTML scanner or header parser to relearn the new hints. Calling `put()` automatically resets the entry's age to 0. The next user will get the refreshed hints.

ATS Cache Hit Optimization (Stale TTL):
If the TTL has expired but the HTTP response is served directly from the ATS Disk Cache, the plugin behaves differently depending on the mode:
* **Auto-Learn**: The plugin knows the HTML body is frozen in the ATS cache and cannot yield new hints. Instead of using a stale TTL indefinitely, the plugin simply calls `touch()` to reset the TTL clock for another cycle (age reset to 0 without re-scanning).
* **Origin-Forward**: The plugin does not `touch()` the entry. The entry remains flagged as stale on subsequent ATS cache hits until an actual origin request occurs (ATS cache miss) which triggers an origin header re-parsing, or until it reaches the eviction threshold.

Stale Eviction (`--stale-evict-after`):
When `--stale-evict-after N` is set, the plugin computes a combined eviction threshold as `hints_ttl + stale_evict_after`. This combined value is passed to `HintsCache::get()`, which checks the entry age after returning the cached links. If the entry's age **strictly exceeds** this combined threshold (`age > hints_ttl + stale_evict_after`), the entry is immediately removed from the cache (note: `get()` is therefore non-const). An entry at exactly `age == hints_ttl + stale_evict_after` survives for one more second. If either `hints_ttl` or `stale_evict_after` is 0, eviction is disabled entirely. 

The request that triggers this eviction exhibits a specific behavior: it receives the 103 response using the just-deleted links (Stale While Revalidate), but it does **NOT** trigger a background re-learn. This happens because `get()` deletes the entry before `get_age()` is called in the remap phase; `get_age()` then returns -1, making the plugin believe the entry is fresh (`needs_relearn=false`). Because of this, the scanner bypasses the current request. It is the **NEXT request** (which encounters a complete cache miss) that will trigger a cold-start re-learn. This mechanism effectively purges abandoned URLs from the cache to prevent memory leaks on sites with infinite URL spaces.

Difference summary:
| Mechanism | Entry after trigger? | Re-learn action | Stale hints served how long? |
|-----------|----------------------|-----------------|-------------------------------|
| TTL (hints-ttl) | Kept | Origin hit: `put()` (scan)<br>ATS Cache hit: `touch()` (auto-learn only) | Indefinitely (as long as traffic keeps refreshing it) |
| Stale Evict | Deleted immediately | None (Scanner skipped). Next request is a cold-start miss. | Exactly once (the triggering request) |

### Disk Persistence Internals

If disk storage is enabled, the plugin writes to disk using an atomic write then rename pattern to prevent file corruption during crashes. 

1. Write to a temporary file (`.tmp`) with the `O_EXCL` flag to prevent race conditions and symlink attacks. (Note: Upon ATS startup, the plugin proactively unlinks any stale `.tmp` files leftover from prior crashes to ensure this step succeeds).
2. Call `fdatasync` to flush the kernel buffer directly to stable hardware storage.
3. Call `rename` to atomically replace the old cache file. 
4. Check generation: The internal `is_dirty` flag is only cleared if the `dirty_generation_` counter remained unchanged during the entire I/O operation. This protects against race conditions, ensuring that concurrent `put()` calls during disk writing are successfully saved on the next interval.

Graceful Shutdown: When ATS shuts down gracefully, the `HintsCache` destructor explicitly flushes any pending dirty data to disk, guaranteeing that data waiting on the throttle interval is safely persisted.

Magic Number and Cold Starts:
The binary persist file starts with a 4-byte magic number: `0x45480003` (Version 3).
V1 (`0x45480001`) and V2 (`0x45480002`) files are rejected on load and trigger a silent cold start  -- all previous cache is dropped. There is no backward-compatible migration path; upgrading from an older plugin version always requires a fresh warm-up cycle.

Cold-Upgrade Validation & Protection:
During loading, every persisted link is re-validated against the current version's validator. Links that were valid in older versions but are now invalid will be discarded silently. Furthermore, if a persisted file contains a timestamp from the future (due to clock skew or tampering), it is immediately clamped to `now` to protect the LRU and TTL logic. Additionally, there are two distinct bounds checks during load: if an individual link exceeds 8192 bytes, only that specific link is silently skipped and the load continues; however, if a single URL in the persisted file contains more than 1,000 links in total, the plugin aborts the load entirely and initiates a cold start to protect memory.

Restart Behavior (request_count reset):
Note that `request_count` is NOT persisted to disk, only the learned links (URLs and their rel-type hints) are saved. When ATS restarts and loads the cache from disk, all URLs start with `request_count = 0`. Therefore, it will require additional requests to hit the `min-hit-count` threshold before ATS begins sending 103 responses again for those URLs.

### Concurrency Model
The plugin uses a strict lock order to prevent deadlocks:
1. `persist_mutex_` (Serializes disk I/O)
2. `mutex_` (Protects the memory map and LRU list)
During a disk write, it snapshots the map under `mutex_`, releases `mutex_`, and performs all file I/O operations without blocking readers.

## Statistics
The plugin provides custom statistics registered via the ATS statistics API. Stats are created with `TS_STAT_NON_PERSISTENT`.

> **Note on `traffic_ctl` visibility:** `traffic_ctl metric get <stat_name>` requires both `traffic_server` AND `traffic_manager` to be running. In environments where only `traffic_server` is active (e.g., Docker containers or test harnesses), `traffic_ctl` will return an error. A more reliable alternative for testing is to use the `--debug-header` option and inspect the `x-early-hints-status` response header directly.

* `plugin.early_hints.103_sent`: Total number of 103 responses successfully sent to clients.
* `plugin.early_hints.103_send_failed`: Number of times `TSHttpTxnSendEarlyHints` returned `TS_ERROR` (client disconnect, H2 protocol error, etc.).
* `plugin.early_hints.103_skipped_bot`: Number of times sending a 103 was skipped because the client was identified as a bot.
* `plugin.early_hints.103_skipped_h1`: Number of times sending a 103 was skipped because the client connected via HTTP/1.x.
* `plugin.early_hints.103_skipped_non_nav`: Number of times sending a 103 was skipped because the `Sec-Fetch-Mode` header was present but set to a non-navigate value (e.g., `cors`, `no-cors`, `same-origin`, `websocket`). Note: if the `Sec-Fetch-Mode` header is completely absent, the request is treated as a valid navigate request and this stat is NOT incremented.
* `plugin.early_hints.103_skipped_no_hints`: Number of times sending a 103 was skipped because no hints were available after the merge phase (empty merged list).
* `plugin.early_hints.hints_learned`: The number of times the plugin successfully learned hints. Incremented in the following paths: (1) auto-learn scanner transform completion (both end-of-stream and final flush paths in `RESPONSE_TRANSFORM`), (2) origin-forward link extraction from a normal origin response (`READ_RESPONSE_HDR`), and (3) origin-forward self-healing from ATS cached response headers (`READ_CACHE_HDR`). Note: the H1 cache-hit path in `READ_CACHE_HDR` that calls `get()` to increment `request_count` does NOT increment this stat. `get()` is only for traffic gating, not learning. A `stat_learned_emitted` guard prevents double-counting in combined mode (where both origin-forward and auto-learn may fire for the same request).
* `plugin.early_hints.purge_rate_limited`: Number of times a purge request with a valid secret was rejected because the per-remap rate limit (`--purge-limit` within `--purge-cooldown` seconds) was exceeded. A `TSNote` is written to diags.log for each blocked purge.
