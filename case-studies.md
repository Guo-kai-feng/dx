# Case Studies

## Case Study A: Webpack Bundle + Axios Interceptor Signature

### Target
Toutiao `_signature` parameter in API requests (`/article/v4/tab_comments/`)

### Key Files
- `tt_pc_bricks.ec0a9f54.js` — Main webpack bundle with axios interceptor
- `acrawler.js` — ByteDance SDK with VM-protected signature generation

### Reversal Steps

**Step 1: Locate the interceptor**
```
search_in_sources: "axios.interceptors.request.use"
```

Found code pattern:
```javascript
Z.interceptors.request.use((function(e) {
  // e contains request config
  // _signature is added here
}));
```

**Step 2: Trace back to find _signature source**
```
search_in_sources: "_signature"
trace_function: "_signature generation function"
```

**Step 3: Identify acrawler.js**
The interceptor calls into `acrawler.js`, which contains a VM-protected signature generator (`_$jsvmprt` bytecode interpreter).

**Step 4: Decision point — simulation vs pure algorithm**
The `acrawler.js` is 71KB with VM bytecode. Attempting pure algorithm would require decompiling the VM. Environment simulation is the pragmatic choice.

**Step 5: Build environment simulation**
See `references/environment-simulation.md` for the complete sandbox implementation.

**Step 6: Critical discovery — JSONP dependency**
The signature was 47 chars (expected 147). Root cause: `acrawler.js` uses JSONP during `init()` to fetch configuration:

```javascript
// These script src assignments must trigger real HTTP requests
script.src = 'https://xxbg.snssdk.com/websdk/v1/p?callback=_9608_...';
script.src = 'https://xxbg.snssdk.com/websdk/v1/getInfo?q=...&callback=_5741_...';
```

**Step 7: Fix — intercept and execute JSONP**
```javascript
const origCreateElement = sandbox.document.createElement;
sandbox.document.createElement = function(tag) {
  const el = origCreateElement.call(this, tag);
  if (tag === 'script') {
    Object.defineProperty(el, 'src', {
      set(url) {
        if (url && url.startsWith('http')) {
          pendingJsonp.push(url);
        }
        this._src = url;
      }
    });
  }
  return el;
};
```

After `init()`, execute all pending JSONP requests through Node.js `https` module and evaluate callbacks in VM context.

**Result:** Signature matches browser exactly — 147 characters, deterministic.

---

## Case Study B: VMP-Protected Algorithm → Pure Python

### Target
Doubao (豆包) `a_bogus` signature and `strData` encryption for SSE chat API

### Protection Layers
- `a_bogus` — Core request signature
- `X-Bogus` — Separate signature system (NOT the same as `a_bogus`)
- `strData` — Encrypted request body
- Multiple environment detection points

### Reversal Steps

**Step 1: Initial direction — environment simulation**
AI attempted to patch Node.js environment:
- `document.all` detection → C-language patched proxy object
- Various `window` properties
- Browser-specific APIs

**Result:** Request still blocked after 20+ patches. Direction was wrong.

**Step 2: Strategic pivot**
```
"Not limited to environment simulation. Extract the algorithm directly, implement in pure Python."
```

**Step 3: Reverse parsing (反解析)**
Instead of forward-engineering, decrypt browser-generated `strData` back to plaintext:
```
"Don't send requests yet. Decrypt this strData to plaintext so we can compare."
```

By comparing decrypted browser data against locally generated data, AI identified missing fields and incorrect values.

**Step 4: Byte-by-byte comparison**
```
"Compare local strData with browser version. Same length? Same structure?"
```

**Step 5: Iterative correction**
Using the decrypted "correct answer" as reference, AI iteratively fixed:
- Missing fields in plaintext structure
- Incorrect encoding methods
- Wrong parameter ordering

**Result:** Pure Python implementation, no browser dependency, no automation tools, no environment simulation. Full protocol implementation from guest registration to SSE chat.

### Key Lessons
1. **Environment simulation hit a wall** — detection points were too numerous
2. **Reverse parsing was the breakthrough** — knowing the plaintext structure made correction trivial
3. **Short commands worked better** — 107 user messages, most under 30 characters
4. **Human made the pivot decision** — AI executed well but needed direction change

---

## Case Study C: Multi-Stage Captcha (Click + Slide)

### Target
Aliyun captcha — single API (`POST /api/v1/captcha/verify`) with three scenes:
- `scene=DO_NOTHING` — Initialize/fetch captcha
- `scene=Click` — Submit click positions
- `scene=Puzzle` — Submit slide distance

### Fields to Reverse
- `did` — Device ID
- `ua` — Environment fingerprint (encrypted)
- `s` — Request signature
- `payload` — Image/coordinate data
- `actions` — Mouse trajectory simulation

### Reversal Steps

**Step 1: Interface state machine**
```
"Analyze the verify API. What are the different scene values and what does each do?"
```

AI identified three scenes and their field requirements.

**Step 2: Field classification**
```
"Classify each field: which are fixed, which are runtime-generated, which affect server validation?"
```

Result:
| Field | Type | Notes |
|-------|------|-------|
| `did` | Fixed | Device identifier, generated once |
| `ua` | Runtime | Browser fingerprint, changes per request |
| `s` | Runtime | Signature, depends on timestamp + request fields |
| `payload` | Runtime | Image data for click/slide |
| `actions` | Runtime | Simulated mouse path |

**Step 3: JS search by keywords**
```
search_in_sources: "DO_NOTHING"
search_in_sources: "captchaConfig"
search_in_sources: "payload"
search_in_sources: "actions"
search_in_sources: "encrypt"
search_in_sources: "Base64"
```

**Step 4: Module decomposition**
AI grouped the code into independent modules:
- Custom Base64 codec
- White-box AES/CBC encryption
- `s` signature generation (binary structure)
- `did` generation
- `ua` fingerprint collection
- `actions` trajectory encoding

**Step 5: Hook and breakpoint validation**
```
Hook: JSON.stringify, fetch, localStorage.setItem, document.cookie
Breakpoint: before payload encryption, before s generation, before actions encoding
```

**Step 6: Module-by-module translation**
Each module was extracted and verified independently:
1. Base64 codec → Python, verify encoding/decoding
2. AES encryption → Python, verify with known key/IV
3. Signature generation → Python, verify against browser
4. Fingerprint → Python, verify field values match
5. Trajectory → Python, verify format matches

**Result:** Complete Python implementation of click and slide captcha bypass.

---

## Case Study D: WebSocket Protocol Analysis

### Target
WebSocket-based real-time data API

### Reversal Steps

**Step 1: List and inspect WebSocket connections**
```
list_websockets: Show all connections with URLs and protocols
```

**Step 2: Capture message patterns**
```
get_websocket_messages: Get all messages, grouped by direction (sent/received)
```

**Step 3: Correlate with UI actions**
```
Perform action X on page
get_websocket_messages again
Compare: what new messages appeared?
```

**Step 4: Find message handlers in JS**
```
search_in_sources: "WebSocket" OR "new WebSocket" OR "ws.onmessage"
search_in_sources: "JSON.parse" near websocket code
```

**Step 5: Set breakpoints on message processing**
```
set_breakpoint_on_text: "ws.onmessage" or "socket.addEventListener('message'"
get_paused_info: Inspect message parsing logic
```

**Result:** Full protocol documentation with message types, encoding, and response handling.

---

## Quick Decision Tree

```
Starting a new reversal task:
│
├─ Is it a standard HTTP API with encrypted params?
│  ├─ Yes → Start with search_in_sources for param name
│  │         → set_breakpoint_on_text at encryption function
│  │         → Decide: pure algorithm or env simulation
│  │
│  └─ No → Continue...
│
├─ Is it WebSocket-based?
│  ├─ Yes → list_websockets → get_websocket_messages
│  │         → search_in_sources for WS handlers
│  │         → break on message processing code
│  │
│  └─ No → Continue...
│
├─ Is it a captcha/multi-stage flow?
│  ├─ Yes → Map the state machine first (what are the stages?)
│  │         → Classify fields by type (fixed/runtime/validation)
│  │         → Decompose into independent modules
│  │         → Hook + breakpoint per module
│  │
│  └─ No → Continue...
│
├─ Is the code webpack-bundled and minified?
│  ├─ Yes → list_scripts (find main bundle)
│  │         → search_in_sources (find param references)
│  │         → trace_function (track calls without breakpoints)
│  │
│  └─ No → Direct source analysis
│
└─ Does it use VM protection (VMP, bytecode)?
   ├─ Yes → Prefer environment simulation
   │         → See environment-simulation.md
   │         → Check for JSONP/network dependencies
   │
   └─ No → Prefer pure algorithm extraction
             → Use reverse parsing (反解析)
             → Implement in Python/Node.js
```
