# MCP Tools for JS Reverse Engineering

## Table of Contents

- [Tool Inventory Overview](#tool-inventory-overview)
- [Page & Navigation Tools](#page--navigation-tools)
- [Script Analysis Tools](#script-analysis-tools)
- [Breakpoint & Execution Control](#breakpoint--execution-control)
- [Function Tracing & Injection](#function-tracing--injection)
- [Network Analysis Tools](#network-analysis-tools)
- [Anti-Detection Browser Tools](#anti-detection-browser-tools)
- [Tool Selection Guide by Task](#tool-selection-guide-by-task)
- [MCP Configuration](#mcp-configuration)

## Tool Inventory Overview

| Tool | Category | Purpose |
|------|----------|---------|
| `select_page` | Navigation | List/select pages, switch debug target |
| `new_page` | Navigation | Create new page and navigate to URL |
| `navigate_page` | Navigation | Navigate, back, forward, reload |
| `select_frame` | Navigation | Switch iframe execution context |
| `take_screenshot` | Navigation | Capture page screenshot |
| `list_scripts` | Script Analysis | List all loaded JS scripts |
| `get_script_source` | Script Analysis | Get script source (supports line range) |
| `save_script_source` | Script Analysis | Save full script to local file |
| `search_in_sources` | Script Analysis | Search string/regex across all scripts |
| `set_breakpoint_on_text` | Breakpoint | Set breakpoint by code text search |
| `break_on_xhr` | Breakpoint | Set XHR/Fetch breakpoint by URL pattern |
| `remove_breakpoint` | Breakpoint | Remove breakpoint by ID/URL/all |
| `list_breakpoints` | Breakpoint | List all active breakpoints |
| `get_paused_info` | Breakpoint | Get pause location, call stack, scope vars |
| `pause_or_resume` | Breakpoint | Pause/resume execution |
| `step` | Breakpoint | Step over/into/out |
| `trace_function` | Tracing | Trace any function call (logpoint, no pause) |
| `inject_before_load` | Tracing | Inject script before page loads |
| `list_websockets` | Network | List WebSocket connections |
| `get_websocket_messages` | Network | Get WS messages, filter by type |

## Page & Navigation Tools

### `select_page`

List all open pages and switch the debugging target.

**When to use:** When you need to switch between multiple tabs, or when you first connect and need to see what's available.

```
List all open pages and select page {index} as the debug target.
```

### `new_page`

Create a new page and navigate to a URL.

**When to use:** Starting a fresh reversal session; opening the target site in a clean tab.

```
Create a new page and navigate to {target_url}.
```

### `navigate_page`

Navigate, go back, forward, or reload.

**When to use:** Refreshing after script injection; navigating to a specific page state.

```
Reload the current page.
Navigate to {url}.
```

### `select_frame`

Switch iframe context.

**When to use:** The target site uses iframes and the encryption logic is inside one; captchas are often in iframes.

```
List all iframes and switch to frame {index}.
```

## Script Analysis Tools

### `list_scripts`

List all JS scripts loaded on the page.

**When to use:** Phase 2—identifying which scripts to analyze. Look for the largest files (often webpack bundles) and scripts with suspicious names.

```
List all loaded JS scripts. Show file size and URL for each.
```

**Analysis tip:** Sort by size. The largest script is usually the main webpack bundle containing the app logic. Smaller scripts with cryptic names may be the protection/obfuscation layer.

### `search_in_sources`

Search for strings or regex across ALL scripts.

**When to use:** Phase 2—finding the encryption function or parameter generation code. This is the most frequently used tool.

```
Search all scripts for "sign" and show matching locations with 10 lines of context.
Search all scripts for /_signature|signature/ regex and list all matches.
Search all scripts for "encrypt" OR "CryptoJS" OR "AES" OR "md5".
```

**Search strategy by priority:**
1. Search for the API path string (e.g., `/api/v1/captcha/verify`)
2. Search for the parameter name (e.g., `_signature`, `a_bogus`)
3. Search for standard crypto function names
4. Search for distinctive strings from the request payload

### `get_script_source`

Get a portion of script source code.

**When to use:** After `search_in_sources` finds a match, get surrounding code to understand the context.

```
Get script source from {script_url} lines {start}-{end}.
Get script source from {script_url} character offset {start}-{end}.
```

### `save_script_source`

Save a complete script to a local file.

**When to use:** When you need to analyze a large script offline or search it with local tools.

```
Save the full script from {script_url} to ./scripts/{filename}.js.
```

## Breakpoint & Execution Control

### `set_breakpoint_on_text`

Set a breakpoint by searching for code text. **Especially useful for minified code** where line numbers are meaningless.

**When to use:** Phase 3—when you know a function name or code pattern but not the exact location.

```
Set a breakpoint on the code containing "_signature=".
Set a breakpoint on the code containing "function encryptData".
Set a breakpoint on the code containing "axios.interceptors.request".
```

### `break_on_xhr`

Set XHR/Fetch breakpoint by URL pattern.

**When to use:** When you want to break when a specific API is called, without knowing which JS code initiates it.

```
Break on XHR/Fetch matching URL pattern "*api*signature*".
Break on XHR/Fetch to URLs containing "tab_comments".
```

### `get_paused_info`

Get current pause location, call stack, and scope variables.

**When to use:** Immediately after a breakpoint hits. This is the most important information-gathering tool.

```
Get paused info: show call stack, local variables, and scope chain.
Show the full call stack with function names and locations.
Show all local variables in the current scope.
```

### `step`

Step through code execution.

**When to use:** Tracing through the encryption algorithm step by step to understand the transformation chain.

```
Step into the next function call.
Step over (don't enter function calls).
Step out of the current function.
```

### `trace_function`

Trace function calls without pausing (uses logpoints).

**When to use:** When you want to observe function calls across multiple executions without manually stepping. **Works with webpack bundled internal functions.**

```
Trace function "encryptData", log all calls with parameters and return values.
Trace the function at {script_url}:{line}, capture arguments and return value.
```

**Key advantage:** Unlike breakpoints, tracing does not pause execution. It records all calls and their parameters, which is ideal for analyzing high-frequency functions or multi-step interactions.

### `inject_before_load`

Inject a script before the page loads.

**When to use:** When you need to hook or intercept code before the page's own scripts run. Essential for intercepting `fetch`, `XMLHttpRequest`, `document.cookie`, etc.

```
Inject this script before page loads: {hook_script_content}
```

**Common injection patterns:**
- Hook `fetch`/`XHR` to log all requests
- Hook `document.cookie` to intercept cookie reads/writes
- Override `JSON.stringify` to inspect data structures
- Define global functions before the target script uses them

## Network Analysis Tools

### `list_websockets`

List all WebSocket connections.

**When to use:** Analyzing WebSocket-based protocols (common in chat apps, real-time data feeds).

```
List all WebSocket connections on the current page.
```

### `get_websocket_messages`

Get WebSocket messages with optional filtering.

**When to use:** Deep analysis of WebSocket protocol after listing connections.

```
Get all WebSocket messages from connection {index}, grouped by type.
Get WebSocket messages containing "{search_term}".
```

## Anti-Detection Browser Tools

### camoufox-reverse / Patchright-based browsers

These are not MCP tools per se, but specialized browsers that work with MCP:

| Browser Tool | Based On | Best For |
|--------------|----------|----------|
| `js-reverse-mcp` (built-in) | Patchright | General JS reverse with built-in anti-detection |
| `camoufox-reverse MCP` | Camoufox | Sites with heavy automation detection (知乎, Google) |

**Anti-detection capabilities:**
- `webdriver` property hidden
- Plugin array simulation
- `chrome.runtime` presence
- Permission API simulation
- WebGL/Canvas fingerprint consistency
- User agent and navigator properties consistency

## Tool Selection Guide by Task

### Task: "Find the encryption function for parameter X"

```
1. search_in_sources → Find code containing "X" or the API path
2. get_script_source → Read surrounding code context
3. set_breakpoint_on_text → Set breakpoint on encryption function
4. Trigger action on page
5. get_paused_info → Inspect call stack and variables
6. step → Walk through the algorithm
```

### Task: "Track all requests and their parameters"

```
1. inject_before_load → Inject hook for fetch/XHR + cookie
2. navigate_page → Reload page
3. Perform user actions
4. Check captured logs
```

### Task: "Analyze webpack bundled code"

```
1. list_scripts → Find main bundle (largest file)
2. search_in_sources → Search for parameter name in bundle
3. trace_function → Trace the internal function without setting breakpoints
4. get_script_source → Read the function source once located
```

### Task: "Intercept and analyze WebSocket protocol"

```
1. list_websockets → Find active connections
2. get_websocket_messages → Capture initial messages
3. Perform actions that trigger WS messages
4. get_websocket_messages again → Compare message patterns
5. search_in_sources → Find WS send/message handlers in JS
```

### Task: "Analyze login flow with password encryption"

```
1. inject_before_load → Hook localStorage, cookie, fetch
2. navigate_page → Open login page
3. search_in_sources → Search for "password", "sign", "token"
4. set_breakpoint_on_text → Set breakpoint on password handling code
5. Enter credentials and submit
6. get_paused_info → Inspect encryption process
7. step → Trace password transformation
```

### Task: "Captcha bypass (click/slide)"

```
1. navigate_page → Open captcha page
2. search_in_sources → Find captcha-related code: "captcha", "verify", "slide", "click"
3. break_on_xhr → Break on verify API URL pattern
4. Complete captcha manually or analyze image loading
5. get_paused_info → When verify request fires, inspect payload
6. search_in_sources → Find payload generation: "actions", "ua", "s", "did"
7. trace_function → Trace each parameter generation independently
```

### Task: "Cookie generation analysis"

```
1. inject_before_load → Hook document.cookie setter
2. navigate_page → Load page fresh
3. Observe cookie write sequence and values
4. search_in_sources → Find the script writing the cookie
5. set_breakpoint_on_text → Break on the cookie generation function
6. get_paused_info → Inspect fingerprint data going into cookie
```

### Task: "Compare local vs browser-generated signature"

```
1. Generate signature locally with your implementation
2. trace_function → Trace the browser's signature generation
3. Compare outputs byte-by-byte
4. If different, search_in_sources for missing logic
5. get_script_source → Read the discrepancy area
6. Fix and re-verify
```

## MCP Configuration

### js-reverse-mcp (Standard Setup)

```json
{
  "mcpServers": {
    "js-reverse": {
      "command": "npx",
      "args": ["js-reverse-mcp"]
    }
  }
}
```

### js-reverse-mcp (Connecting to Running Chrome)

Use when you need a pre-logged-in browser session:

```bash
# macOS
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug

# Windows
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="%TEMP%\chrome-debug"
```

```json
{
  "mcpServers": {
    "js-reverse": {
      "command": "npx",
      "args": ["js-reverse-mcp", "--browser-url=http://127.0.0.1:9222"]
    }
  }
}
```

### camoufox-reverse MCP

Use for sites with heavy bot detection (知乎, Google, advanced fingerprinting):

```json
{
  "mcpServers": {
    "camoufox": {
      "command": "npx",
      "args": ["camoufox-reverse-mcp"]
    }
  }
}
```

**When to use camoufox vs standard:**
- **Standard (js-reverse-mcp):** Most sites, internal corporate apps, standard webpack bundles
- **Camoufox:** Sites with advanced automation detection, canvas/WebGL fingerprinting, behavior analysis (知乎, 抖音, Google)
