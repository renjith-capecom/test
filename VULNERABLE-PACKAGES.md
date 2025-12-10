# CVE-2025-55182 - Vulnerable npm Packages Research

This document analyzes popular npm packages that include dangerous Node.js modules (`fs`, `child_process`, `vm`) which could be exploited via CVE-2025-55182 if present in a React Server Components webpack bundle.

## Summary

| Module | Risk Level | Popular Packages Using It |
|--------|------------|---------------------------|
| `fs` | **Very High** | fs-extra (145M/week), gray-matter (2.4M/week), multer, sharp |
| `child_process` | **High** | execa (103M/week), shelljs (10M/week), puppeteer, sharp |
| `vm` | **Medium** | ejs (21M/week), pug, handlebars, vm2, safe-eval |
| `module` | **Very Low** | tsx, ts-node, esm-loader, create-require (ESM/CJS interop tools) |

## Packages Using `fs` (File System)

Almost every server-side package uses `fs`. This is the most likely attack vector.

| Package | Weekly Downloads | Description | Attack Impact |
|---------|------------------|-------------|---------------|
| **fs-extra** | 145,671,341 | Extended fs methods (copy, move, etc.) | File read/write |
| **gray-matter** | 2,417,759 | YAML front-matter parser (used by Gatsby, Astro, Next.js blogs) | File read |
| **multer** | ~2,000,000 | File upload middleware for Express | File write |
| **sharp** | ~10,000,000 | Image processing | File read/write |
| **formidable** | ~6,000,000 | Form/file parsing | File read/write |
| **chokidar** | ~70,000,000 | File watcher | File read |
| **glob** | ~80,000,000 | File pattern matching | File read |

### Attack Scenarios with `fs`

1. **Read secrets**: `.env`, `~/.aws/credentials`, private keys
2. **SSH persistence**: Write to `~/.ssh/authorized_keys`
3. **Backdoor**: Append to `~/.bashrc` or `~/.zshrc`
4. **Source tampering**: Overwrite `node_modules/*` for RCE on restart

## Packages Using `child_process`

These packages spawn shell commands and provide **direct RCE**.

| Package | Weekly Downloads | Description | Attack Impact |
|---------|------------------|-------------|---------------|
| **execa** | 103,586,505 | Better child_process wrapper | **Direct RCE** |
| **shelljs** | 10,483,446 | Unix shell commands in Node.js | **Direct RCE** |
| **cross-spawn** | ~100,000,000 | Cross-platform spawn | **Direct RCE** |
| **puppeteer** | ~3,000,000 | Headless Chrome automation | **Direct RCE** |
| **sharp** | ~10,000,000 | Image processing (uses libvips) | **Direct RCE** |
| **node-gyp** | ~15,000,000 | Native addon build tool | **Direct RCE** |

### Common Use Cases

- **PDF generation**: puppeteer, pdf-lib with shell commands
- **Image processing**: sharp, imagemagick wrappers
- **Build tools**: webpack plugins, bundlers
- **CI/CD**: deployment scripts, git operations

## Packages Using `vm` Module

These packages evaluate JavaScript code and could enable **code execution**.

| Package | Weekly Downloads | Description | Attack Impact |
|---------|------------------|-------------|---------------|
| **ejs** | 21,781,369 | Embedded JavaScript templates | **Code execution** |
| **pug** | 1,947,725 | Template engine (formerly Jade) | **Code execution** |
| **handlebars** | ~10,000,000 | Logic-less templates | Limited |
| **vm2** | ~4,000,000 | Sandboxed VM (deprecated, CVE-2023-37466) | **Code execution** |
| **safe-eval** | ~500,000 | "Safe" eval alternative | **Code execution** |
| **lodash.template** | ~5,000,000 | Template strings | **Code execution** |

### Template Engine Risks

EJS specifically uses `vm` for template compilation:
```javascript
// EJS internally does something like:
const fn = new Function('locals', templateCode);
```

If EJS is in the bundle, `vm#runInThisContext` becomes available.

## Real-World Attack Likelihood

### Very Likely (fs)
Almost every Next.js/React app has packages using `fs`:
- Content management (gray-matter for MDX blogs)
- File uploads (multer, formidable)
- Static file serving
- Configuration loading

### Likely (child_process)
Common in apps with:
- Image optimization (sharp, puppeteer)
- PDF generation
- Git operations
- Build/deployment scripts
- External tool integration

### Less Likely (vm)
Present in apps using:
- Server-side templating (EJS, Pug)
- Dynamic code evaluation
- Plugin systems
- Sandboxed execution

### Very Unlikely (module)
The `module` built-in is rarely bundled into webpack:
- ESM/CJS interop tools (tsx, ts-node, esm-loader)
- Build tools that need dynamic require
- Plugin loaders

**Note**: `module#_load` and `module#createRequire` are internal APIs used for module resolution. These are almost never bundled into application code - they're typically used by Node.js tooling at the CLI level, not in webpack bundles.

## Packages Using `module` (Module System)

The `module` built-in provides `createRequire` and internal `_load` functions. **Very rarely bundled**.

| Package | Weekly Downloads | Description | Attack Impact |
|---------|------------------|-------------|---------------|
| **tsx** | ~5,000,000 | TypeScript execute | 2-step RCE (with fs) |
| **ts-node** | ~20,000,000 | TypeScript execution | 2-step RCE (with fs) |
| **@esbuild-kit/esm-loader** | ~1,500,000 | ESM loader for TypeScript | 2-step RCE (with fs) |
| **create-require** | ~1,000,000 | Polyfill for createRequire | 2-step RCE (with fs) |

### Why `module` is Unlikely

1. **CLI tools, not libraries**: tsx, ts-node are run as CLI commands, not bundled
2. **Build-time only**: ESM loaders run during build, not in production bundles
3. **Node.js internal**: `module._load` is an internal API, rarely exposed

### Attack Chain (if available)

```javascript
// Step 1: Write malicious file
{ id: 'fs#writeFileSync', bound: ['/tmp/evil.js', 'module.exports = require("child_process").execSync("whoami")'] }

// Step 2: Load it
{ id: 'module#_load', bound: ['/tmp/evil.js'] }
```

This requires BOTH `fs` AND `module` in the bundle - very unlikely in practice.

## Specific Package Analysis

### sharp (Image Processing)
- Uses both `fs` and `child_process`
- Very popular for Next.js image optimization
- **Attack vector**: `child_process#execSync` or `fs#writeFileSync`

### puppeteer (Browser Automation)
- Uses `child_process` to launch Chrome
- Common for PDF generation, screenshots, scraping
- **Attack vector**: `child_process#spawn`

### gray-matter (Front-matter Parser)
- Uses `fs` to read files
- Extremely common in Next.js/Gatsby/Astro blogs
- **Attack vector**: `fs#readFileSync` (data exfiltration)

### ejs (Template Engine)
- Uses `vm` for template compilation
- Still popular despite security concerns
- **Attack vector**: `vm#runInThisContext`

## Mitigation Recommendations

1. **Upgrade React** to patched versions (19.0.1+, 19.1.2+, 19.2.1+)
2. **Audit dependencies** for dangerous modules
3. **Minimize server-side packages** in RSC bundles
4. **Use serverExternalPackages** in Next.js to exclude dangerous packages from bundling
5. **WAF rules** to block suspicious `$ACTION_` payloads

## Next.js Configuration

To exclude dangerous packages from the webpack bundle:

```javascript
// next.config.js
module.exports = {
  serverExternalPackages: [
    'sharp',
    'puppeteer',
    'execa',
    'shelljs'
  ]
}
```

## Sources

- [npm trends - execa vs shelljs](https://npmtrends.com/execa-vs-shelljs)
- [npm trends - fs-extra](https://npmtrends.com/fs-extra)
- [npm trends - ejs](https://npmtrends.com/ejs)
- [gray-matter - npm](https://www.npmjs.com/package/gray-matter)
- [multer - npm](https://www.npmjs.com/package/multer)
- [vm2 - GitHub](https://github.com/patriksimek/vm2)
- [Node.js VM Security Concerns - Snyk](https://snyk.io/blog/security-concerns-javascript-sandbox-node-js-vm-module/)
