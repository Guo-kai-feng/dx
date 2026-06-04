---
name: js-reverse-ai
description: AI-assisted JavaScript reverse engineering for bypassing obfuscation, deobfuscating code, analyzing encryption algorithms, and extracting API signatures. Use when the task involves JS reverse engineering, analyzing minified/obfuscated JavaScript, extracting sign/token parameters, bypassing anti-debugging, environment simulation (补环境), protocol analysis, or automating browser DevTools for web scraping protection bypass. Covers both "pure algorithm" (纯算) and "environment simulation" (补环境) approaches with AI + MCP tools.
---

# AI-Assisted JS Reverse Engineering

This skill provides a complete workflow for using AI (Claude Code, Cursor, etc.) with MCP tools to reverse engineer obfuscated/minified JavaScript, extract encryption algorithms, and reconstruct API signatures in Python or Node.js.

## Core Philosophy

AI + MCP does not replace the reverse engineer's thinking—it automates repetitive debugging work. The human makes strategic decisions (which direction to go, when to pivot); AI executes the mechanical steps (searching code, setting breakpoints, tracing calls).

**Two strategic approaches:**

| Approach | When to Use | Pros | Cons |
|----------|-------------|------|------|
| **Pure Algorithm** (纯算) | When environment detection is too complex | Stable, no browser dependency, no detection risk | Higher initial analysis cost |
| **Environment Sim** (补环境) | For quick validation or simple protections | Fast to prototype | Fragile, detection points accumulate |

**Key insight:** Environment simulation is a crutch; pure algorithm is the destination. Use simulation for quick validation, but plan to transition to pure algorithm for production.

## Standard Reversal Workflow

All JS reverse tasks follow this master sequence:

```
Network Request Analysis → JS Source Search → Hook/Breakpoint → Variable Observation → Algorithm Extraction → Local Verification
```

### Phase 1: Network Request Analysis

First identify the target API and its protected parameters:

**Common protected parameters to look for:** `sign`, `token`, `_signature`, `w`, `x`, `s`, `a_bogus`, `X-Bogus`, `verify`, `t`, `ts`

For each target request, record:
- Full URL with query parameters
- Request method (GET/POST)
- All query parameters (which are dynamic?)
- Request headers (especially custom ones like `X-Sign`, `Authorization`)
- Request body / payload
- Cookies involved
- Response structure

**MCP command pattern:**
```
Open {target_url}, capture all XHR/Fetch requests, find requests containing {parameter_name} in URL or body. List the full request details including URL, method, headers, payload, and response.
```

### Phase 2: Locate the Entry Point

Search the JS source code for the parameter generation logic.

**Search keywords by priority:**

1. **API path strings** - `/api/v1/captcha/verify`, `/article/v4/tab_comments/`
2. **Parameter names** - `sign`, `signature`, `token`, `a_bogus`, `_signature`
3. **Standard functions** - `JSON.stringify`, `encodeURIComponent`, `btoa`, `atob`, `fetch`, `XMLHttpRequest`
4. **Crypto indicators** - `CryptoJS.MD5`, `CryptoJS.SHA256`, `md5`, `sha256`, `AES`, `RSA`, `encrypt`, `decrypt`
5. **Storage access** - `localStorage.setItem`, `document.cookie`, `sessionStorage`
6. **Obfuscation markers** - `eval`, `Function`, `_0x`, `window['']` dynamic property access

**MCP command pattern:**
```
List all loaded JS scripts on the page. Search all scripts for "{param_name}" and "{api_path}". Show me the matching code locations with surrounding context.
```

### Phase 3: Set Breakpoints and Observe

Once candidate functions are identified, use breakpoints to confirm the data flow.

**Optimal breakpoint locations:**
- Before request is sent (axios interceptor, fetch wrapper)
- Parameter concatenation/joining code
- Encryption function entry points
- Before/after `JSON.stringify`
- `fetch` or `XMLHttpRequest.send`
- Cookie write locations (`document.cookie =`)
- `localStorage.setItem` calls

**What to inspect when breakpoint hits:**
- `arguments` object (all input parameters)
- `params`, `headers`, `payload`, `data`, `config` variables
- `this` context
- Call stack (how did we get here?)
- Local scope variables

**MCP command pattern:**
```
Set a breakpoint on the function at {url}:{line_number}. Trigger the request by {user_action}. When breakpoint hits, show me the call stack, all arguments, and local variables. Step through the encryption function and record the input/output at each step.
```

### Phase 4: Hook Key Functions

For complex pages, use hooks to observe behavior without pausing execution.

**Common hook targets:**

```javascript
// Hook fetch
const origFetch = window.fetch;
window.fetch = function(...args) {
    console.log('[HOOK fetch]', args);
    console.trace();
    return origFetch.apply(this, args);
};

// Hook XHR
const origOpen = XMLHttpRequest.prototype.open;
const origSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open = function(method, url) {
    this._url = url; this._method = method;
    return origOpen.apply(this, arguments);
};
XMLHttpRequest.prototype.send = function(body) {
    console.log('[HOOK XHR]', this._method, this._url, body);
    console.trace();
    return origSend.apply(this, arguments);
};

// Hook JSON.stringify
const origStringify = JSON.stringify;
JSON.stringify = function(...args) {
    console.log('[HOOK stringify]', args);
    console.trace();
    return origStringify.apply(this, args);
};

// Hook cookie
Object.defineProperty(document, 'cookie', {
    get() { /* log access */ },
    set(v) { console.log('[HOOK cookie]', v); /* ... */ }
});
```

**MCP command pattern:**
```
Inject this hook script: {hook_code}. Then trigger {action} and capture all console output related to {target_param}.
```

### Phase 5: Module Decomposition

Decompose the encryption logic into independent modules. Do not try to understand everything at once—separate then conquer.

**Typical module categories:**
- **Custom encoding** (custom Base64 variants, XOR, byte manipulation)
- **Encryption layer** (AES/CBC, AES/ECB, RSA, SM2, SM4, custom ciphers)
- **Signature generation** (HMAC, salted hash, request fingerprint)
- **Device fingerprint** (canvas, WebGL, navigator properties, screen info)
- **Behavior simulation** (mouse trajectory, click timing, scroll events)
- **Payload encoding** (protobuf, custom binary format, gzip+base64)

For each module, determine: input → processing → output. Verify each module independently against browser behavior.

### Phase 6: Algorithm Extraction

**For pure algorithm approach:**
1. Trace the parameter generation chain step by step
2. For each step, extract the exact algorithm (which crypto primitive, what key, what mode)
3. Reimplement in Python/Node.js
4. Compare output byte-by-byte with browser output

**For environment simulation approach:**
See `references/environment-simulation.md` for the full environment patching guide.

**Critical technique—reverse parsing (反解析):**
Instead of forward-engineering the algorithm, decrypt the browser-generated ciphertext back to plaintext to see the expected structure. Knowing the "correct answer" makes fixing your implementation much faster than blind debugging.

```
Do not send requests yet. Decrypt this browser-generated {param} back to plaintext so we can compare structures.
```

### Phase 7: Verification

Verification is the only way to confirm correctness. Do not ask AI "is this right?"—make it compare against real browser data byte-by-byte.

**Verification checklist:**
- [ ] Same input → same output (deterministic)
- [ ] Different input → different output
- [ ] Output length matches browser-generated version
- [ ] Output pattern matches (e.g., prefix `o00f`)
- [ ] API request with generated parameter succeeds
- [ ] Long-running test (100+ requests) without failure

## Four Common Reversal Scenarios

### Scenario A: URL Parameter Signature

Target: `sign`, `signature`, `_signature`, `s`, `w`, `x`

Analysis points:
- Which original parameters participate in signing?
- Is timestamp involved? Random number? Fixed salt?
- What hash/digest algorithm? (MD5, SHA1, SHA256, SM3, custom)
- Is result Base64/URL-encoded/Hex-encoded?
- Sign length and pattern (constant vs variable)

### Scenario B: Cookie Generation

Target: `document.cookie` writes before API calls

Hook `document.cookie`, then check:
- Which script writes the cookie?
- What's the raw value before encoding?
- Is encryption used?
- Does it depend on browser fingerprint (canvas, WebGL, fonts)?
- Does it depend on timestamp or user agent?

### Scenario C: Request Header Signature

Target: `Authorization`, `X-Sign`, `X-Token`, `X-Timestamp`, `X-Nonce`

Look at the unified request wrapper (axios interceptor, fetch wrapper). Check:
- Header value generation timing (before each request? cached?)
- Dependency on request URL, method, body
- Crypto algorithm and key source

### Scenario D: Encrypted Request Body

Target: Request body is ciphertext instead of plaintext JSON

Analysis points:
- Where is plaintext data generated?
- Where is encryption function called?
- Algorithm: AES (which mode?), RSA, SM2, SM4, custom?
- Key/IV/PublicKey source (hardcoded? exchanged? derived?)
- Is result double-encoded (encrypt then base64)?

## Prompt Engineering for JS Reverse

### Effective Short Commands

Long prompts dilute focus. Use concise, direct instructions:

| Instead of... | Use... |
|---------------|--------|
| "Can you please analyze this JavaScript code and tell me what the encryption algorithm might be?" | "Search for encrypt function, show me the algorithm." |
| "It seems like the signature is not matching, could you check what's wrong?" | "Signature is wrong. Compare browser vs local byte-by-byte." |
| "Please continue working on this problem and let me know when you find something" | "Continue until fully successful. Do not stop." |
| "I think maybe we should try a different approach" | "Switch to pure algorithm. Ignore environment simulation." |

### Strategic Intervention Points

The human must intervene at decision points, not execution steps:

1. **Direction selection** — "Use pure algorithm, not environment simulation"
2. **Pivot when stuck** — "Environment patching is hitting too many detection points. Switch approaches."
3. **Validation standard** — "The signature must be correct. Anything abnormal indicates an error."
4. **Scope control** — "Don't send requests yet. Just decrypt and compare structures."
5. **Persistence** — "Continue until fully successful. Do not stop."

## Environment Detection Bypass Reference

Common anti-debugging and environment checks with bypass strategies:

| Detection | Method | Bypass |
|-----------|--------|--------|
| `toString.call(window)` | Should be `[object Window]` | Hook `Object.prototype.toString` in VM |
| `toString.call(document)` | Should contain `Document` | Set `Symbol.toStringTag = 'HTMLDocument'` |
| `toString.call(navigator)` | Should be `[object Navigator]` | Set `Symbol.toStringTag = 'Navigator'` |
| `createElement.toString()` | Must contain `native code` | Wrap with `nativeFn()` helper |
| `typeof process` | Must be `undefined` | Do not define `process` in sandbox |
| `navigator.webdriver` | Must be `false` | Set to `false` explicitly |
| `_phantom`, `callPhantom` | Must not exist | Do not define these globals |
| `document.all` | Special HTMLDDA object, `typeof` is `'undefined'` but callable | Use C patch or special proxy object |
| `instanceof` on undefined | `TypeError` in strict mode | Patch VM interpreter to add safety check |
| `Function.prototype.toString` | Detect code tampering | Use native function wrapper |

For complete environment simulation procedures, see `references/environment-simulation.md`.

## Reference Documents

- **`references/mcp-tools.md`** — Complete inventory of MCP tools for JS reverse engineering, organized by use case with specific command patterns for each tool
- **`references/environment-simulation.md`** — Full guide to environment simulation (补环境): VM setup, detection bypass implementation, JSONP interception, and troubleshooting
- **`references/case-studies.md`** — Detailed walkthroughs of real reversal cases: signature extraction from webpack-bundled sites, VMP-protected code, and anti-detection browser automation

## Quick Command Reference

```
# Phase 1: Request analysis
"Open {url}, list all XHR/Fetch requests, find those with {param} parameter"

# Phase 2: Source search
"List all JS scripts, search for '{keyword}' across all sources, show 20 lines of context"

# Phase 3: Breakpoint
"Set breakpoint at {url}:{line}, trigger {action}, show call stack and variables when hit"

# Phase 4: Hook
"Inject hook for {fetch|XHR|JSON.stringify|cookie}, trigger {action}, capture all calls"

# Phase 5: Trace
"Use trace_function to track '{function_name}', show all calls with parameters"

# Phase 6: Extract
"Step through the encryption function, record input/output at each transformation step"

# Phase 7: Verify
"Compare generated {param} with browser version: same length? same pattern? API accepts it?"
```
