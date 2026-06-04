# Environment Simulation (补环境) Guide

## When to Use Environment Simulation

Use environment simulation when:
- The target code is heavily obfuscated but runs in a standard browser environment
- Quick validation is needed before investing in pure algorithm extraction
- The code uses many browser APIs that would be tedious to reverse individually
- The protection is based on environment checks rather than complex cryptography

**Do NOT use when:**
- The code uses VM-based protection (VMP, bytecode interpreters) with many nested detection points
- The site has server-side environment validation beyond client-side checks
- You need long-term stability (pure algorithm is always more stable)

## Architecture Overview

```
Node.js VM Context
├── vm.runInNewContext() or vm.runInContext()
├── Sandbox object (simulated browser environment)
│   ├── window (global object)
│   ├── document (DOM simulation)
│   ├── navigator (browser fingerprint)
│   ├── location, history, screen
│   ├── localStorage, sessionStorage
│   ├── fetch, XMLHttpRequest
│   └── ... other browser APIs
├── Target JS code (acrawler.js, sign.js, etc.)
└── Your calling code (initializes sandbox, invokes sign function)
```

## Core Sandbox Implementation

### Minimal Sandbox Setup

```javascript
const vm = require('vm');
const axios = require('axios');

// Create sandbox with essential browser globals
const sandbox = {
  // Global object self-reference
  window: undefined,
  globalThis: undefined,
  
  // Console
  console,
  
  // Timers
  setTimeout,
  setInterval,
  clearTimeout,
  clearInterval,
  
  // Required constructors
  Object,
  Array,
  String,
  Number,
  Boolean,
  Date,
  RegExp,
  Error,
  TypeError,
  RangeError,
  SyntaxError,
  ReferenceError,
  Promise,
  JSON,
  Math,
  parseInt,
  parseFloat,
  isNaN,
  isFinite,
  encodeURIComponent,
  decodeURIComponent,
  escape,
  unescape,
  
  // Navigator
  navigator: {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    language: 'zh-CN',
    languages: ['zh-CN', 'zh', 'en'],
    platform: 'MacIntel',
    hardwareConcurrency: 8,
    maxTouchPoints: 0,
    vendor: 'Google Inc.',
    webdriver: false,
    plugins: createFakePlugins(),
    mimeTypes: createFakeMimeTypes(),
    onLine: true,
    cookieEnabled: true,
    pdfViewerEnabled: true,
    javaEnabled: () => false,
    // Media devices
    mediaDevices: {
      enumerateDevices: () => Promise.resolve([])
    },
    // Permissions
    permissions: {
      query: () => Promise.resolve({ state: 'prompt' })
    },
    // Bluetooth
    bluetooth: undefined,
    // USB
    usb: undefined,
    // Keyboard
    keyboard: undefined,
    [Symbol.toStringTag]: 'Navigator'
  },
  
  // Screen
  screen: {
    width: 1470,
    height: 956,
    availWidth: 1470,
    availHeight: 919,
    availLeft: 0,
    availTop: 25,
    colorDepth: 24,
    pixelDepth: 24,
    [Symbol.toStringTag]: 'Screen'
  },
  
  // Location
  location: {
    href: 'https://www.toutiao.com/article/7630793912500437540/',
    protocol: 'https:',
    host: 'www.toutiao.com',
    hostname: 'www.toutiao.com',
    port: '',
    pathname: '/article/7630793912500437540/',
    search: '',
    hash: ''
  },
  
  // History
  history: {
    length: 2,
    pushState: () => {},
    replaceState: () => {},
    back: () => {},
    forward: () => {},
    go: () => {},
    [Symbol.toStringTag]: 'History'
  },
  
  // Document (simplified)
  document: {
    createElement: nativeFn('createElement', function(tag) {
      // Hook: track script tag creation for JSONP
      if (tag === 'script') {
        return createScriptElement();
      }
      if (tag === 'canvas') {
        return createFakeCanvas();
      }
      if (tag === 'div' || tag === 'span' || tag === 'a') {
        return createBasicElement(tag);
      }
      return {};
    }),
    getElementById: () => null,
    getElementsByTagName: () => [],
    getElementsByClassName: () => [],
    querySelector: () => null,
    querySelectorAll: () => [],
    documentElement: { style: {} },
    body: {},
    head: {},
    cookie: '',
    readyState: 'complete',
    addEventListener: () => {},
    removeEventListener: () => {},
    createTextNode: (text) => text,
    [Symbol.toStringTag]: 'HTMLDocument',
    // Special: document.all handling
    all: createDocumentAll()
  },
  
  // Storage
  localStorage: {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; },
    clear() { this._data = {}; },
    get length() { return Object.keys(this._data).length; },
    key(i) { return Object.keys(this._data)[i] || null; }
  },
  sessionStorage: {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; },
    clear() { this._data = {}; },
    get length() { return Object.keys(this._data).length; },
    key(i) { return Object.keys(this._data)[i] || null; }
  },
  
  // IndexedDB (stub)
  indexedDB: {
    open: () => ({ result: {}, error: null, onsuccess: null, onerror: null })
  },
  
  // Request API
  Request: function() {},
  Headers: function() {},
  Response: function() {},
  
  // Other globals
  location: undefined, // Will be set to location object
  top: undefined,
  parent: undefined,
  self: undefined,
  opener: null,
  devicePixelRatio: 2,
  innerWidth: 1470,
  innerHeight: 919,
  outerWidth: 1470,
  outerHeight: 956,
  screenX: 0,
  screenY: 25,
  screenLeft: 0,
  screenTop: 25,
  length: 0,
  closed: false,
  status: '',
  name: '',
  customElements: { define: () => {}, get: () => undefined },
  
  // No Node.js indicators
  process: undefined,
  Buffer: undefined,
  __dirname: undefined,
  __filename: undefined,
  require: undefined,
  module: undefined,
  exports: undefined
};

// Self-references
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
sandbox.top = sandbox;
sandbox.parent = sandbox;
sandbox.location = sandbox.location;
```

### Helper Functions

```javascript
// Native function wrapper - preserves toString() as "native code"
function nativeFn(name, fn) {
  return new Proxy(fn, {
    apply(target, thisArg, args) {
      return target.apply(thisArg, args);
    },
    get(target, prop) {
      if (prop === 'toString') {
        return function() {
          return `function ${name}() { [native code] }`;
        };
      }
      return target[prop];
    }
  });
}

// Document.all - special HTMLDDA object
// typeof document.all === 'undefined' in browsers
function createDocumentAll() {
  const all = function() {};
  all.length = 0;
  all.item = () => null;
  all.namedItem = () => null;
  all[Symbol.toStringTag] = 'HTMLAllCollection';
  // typeof returns 'undefined' for this object
  return new Proxy(all, {
    get(target, prop) {
      if (prop === Symbol.toStringTag) return 'HTMLAllCollection';
      if (typeof prop === 'symbol') return target[prop];
      if (prop === 'length') return 0;
      if (prop === 'item') return () => null;
      if (prop === 'namedItem') return () => null;
      return undefined;
    }
  });
}

// Fake plugins array
function createFakePlugins() {
  const plugins = [
    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', version: 'undefined', length: 1, item: () => null },
    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', version: 'undefined', length: 2, item: () => null }
  ];
  plugins.length = plugins.length;
  plugins.item = nativeFn('item', function(i) { return this[i] || null; });
  plugins.namedItem = nativeFn('namedItem', function(name) { return this.find(p => p.name === name) || null; });
  plugins[Symbol.toStringTag] = 'PluginArray';
  plugins.refresh = nativeFn('refresh', function() {});
  return plugins;
}

// Fake canvas with basic toDataURL
function createFakeCanvas() {
  const canvas = {
    getContext: nativeFn('getContext', function(type) {
      if (type === '2d') {
        return {
          fillRect: () => {},
          clearRect: () => {},
          getImageData: () => ({ data: new Uint8ClampedArray(4) }),
          canvas: { width: 300, height: 150 },
          fillText: () => {},
          strokeText: () => {},
          measureText: () => ({ width: 0 })
        };
      }
      return null;
    }),
    toDataURL: nativeFn('toDataURL', function() {
      return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
    }),
    width: 300,
    height: 150,
    style: {},
    getAttribute: () => null,
    setAttribute: () => {}
  };
  return canvas;
}

// Script element with JSONP interception
function createScriptElement() {
  const scriptEl = {
    type: '',
    async: true,
    defer: false,
    onload: null,
    onerror: null,
    _src: ''
  };
  Object.defineProperty(scriptEl, 'src', {
    get() { return this._src; },
    set(v) {
      this._src = v;
      // Intercept HTTP URLs for JSONP handling
      if (v && v.startsWith('http')) {
        this._pendingUrl = v;
      }
    }
  });
  return scriptEl;
}

// Basic DOM element stub
function createBasicElement(tag) {
  return {
    tagName: tag.toUpperCase(),
    style: {},
    attributes: {},
    children: [],
    appendChild: (child) => { children.push(child); return child; },
    removeChild: () => {},
    setAttribute: function(k, v) { this.attributes[k] = v; },
    getAttribute: function(k) { return this.attributes[k] || null; },
    addEventListener: () => {},
    removeEventListener: () => {}
  };
}
```

### VM Setup with Detection Bypasses

```javascript
const vm = require('vm');

function createSecureContext(sandbox) {
  const context = vm.createContext(sandbox);
  
  // CRITICAL: Hook Object.prototype.toString for domDetect bypass
  const origToString = Object.prototype.toString;
  context.Object.prototype.toString = function() {
    if (this === sandbox.window) return '[object Window]';
    if (this === sandbox.document) return '[object HTMLDocument]';
    if (this === sandbox.navigator) return '[object Navigator]';
    if (this === sandbox.history) return '[object History]';
    if (this === sandbox.navigator.plugins) return '[object PluginArray]';
    return origToString.call(this);
  };
  
  return context;
}
```

## JSONP Request Interception

Many SDKs (e.g., acrawler.js) use JSONP to load configuration. In a real browser, `<script src="...">` triggers an actual HTTP request. In Node.js simulation, you must intercept and execute real requests.

```javascript
// JSONP interception pattern
async function executeJsonpRequests(sandbox, context, pendingUrls) {
  const results = [];
  for (const url of pendingUrls) {
    try {
      const response = await axios.get(url, { 
        headers: { 
          'User-Agent': sandbox.navigator.userAgent,
          'Referer': sandbox.location.href
        },
        timeout: 10000
      });
      // Execute JSONP callback in VM context
      vm.runInContext(response.data, context);
      results.push({ url, status: 'success' });
    } catch (err) {
      results.push({ url, status: 'error', error: err.message });
    }
  }
  return results;
}
```

## Critical VM Patches

### instanceof Safety Patch

Some VM-protected code performs `instanceof` on potentially undefined constructors:

```javascript
// Patch the VM interpreter's instanceof operation
// Original: S[R] = S[R] instanceof C
// Fix: Add safety check for undefined/null constructors
function patchInstanceof(vmCode) {
  return vmCode.replace(
    /S\[R\]=S\[R\]instanceof C/g,
    'S[R]=(typeof C==="function"||typeof C==="object"&&C!==null)?S[R]instanceof C:false'
  );
}
```

### RegExp in VM

VM contexts handle RegExp correctly—do not attempt to inject external RegExp objects. If regex appears not to work, check for JavaScript string escaping issues (`\\s` vs `\s` in string literals).

## Detection Bypass Checklist

When a simulated signature differs from the browser version, verify each detection:

| Check | How to Test | Likely Symptom |
|-------|-------------|----------------|
| domDetect | `toString.call(window)` returns `[object Window]` | Signature is shorter or different prefix |
| hookDetect | `fn.toString()` contains `"native code"` | Signature generation throws or returns empty |
| nodeDetect | `typeof process === 'undefined'` | Signature is null/undefined |
| webdriverDetect | `navigator.webdriver === false` | Request rejected, captcha triggered |
| pluginDetect | `navigator.plugins` has `PluginArray` type | Fingerprint-related signature mismatch |
| document.all | `typeof document.all === 'undefined'` | Code path diverges at typeof check |
| instanceof | No TypeError on undefined constructor | VM throws during initialization |
| JSONP | External scripts are actually fetched | Signature shorter, missing configuration data |
| async init | `init()` completes before signature is used | Race condition, intermittent failures |

## Troubleshooting Guide

### "Signature is shorter than browser version"

1. Check JSONP requests are being executed (not just script tags created)
2. Verify `init()` is fully async-completed before calling `sign()`
3. Check for additional network requests during initialization

### "Signature format is different (different prefix/structure)"

1. Check `_byted_param_sw` or equivalent parameter switches are set correctly
2. Verify all environment detection checks are passing
3. Compare the decision path: search for branching logic based on detection results

### "Code works in browser but not in VM"

1. Check for `instanceof` safety (patch VM interpreter)
2. Verify `document.all` handling
3. Check for `window` vs `globalThis` references
4. Look for timing-dependent code (`setTimeout`/`Promise` order)

### "Intermittent failures"

1. Check async initialization timing
2. Verify JSONP callbacks execute in correct order
3. Look for time-dependent components (timestamp, nonce) in signature

## Sample Complete Implementation

```javascript
const { ToutiaoSigner } = require('./sign');

async function main() {
  const signer = new ToutiaoSigner({
    cookie: 'tt_webid=xxx; ttcid=xxx',
    // Optional: custom user agent
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...'
  });
  
  // Async init - includes JSONP requests
  await signer.init();
  
  // Generate signature for any API URL
  const signature = signer.sign(
    'https://www.toutiao.com/article/v4/tab_comments/?aid=24&app_name=toutiao_web&offset=0&count=20&group_id=xxx&item_id=xxx'
  );
  
  console.log('Signature:', signature); // => "_02B4Z6wo00f01..." (147 chars)
  console.log('Length:', signature.length);
}

main().catch(console.error);
```
