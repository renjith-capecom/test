/**
 * Real React Server Components POC for CVE-2025-55182
 * Uses the bundled webpack variant via --conditions webpack react-server
 */

const http = require('http');

// Set up webpack runtime BEFORE importing
global.__webpack_require__ = function(moduleId) {
  console.log('[__webpack_require__]', moduleId);
  return require(moduleId);
};
global.__webpack_chunk_load__ = () => Promise.resolve();

// Load the bundled version via file path (bypassing exports)
const path = require('path');
const fs = require('fs');

// Read and eval the bundled code directly
const bundledPath = path.join(__dirname, '../node_modules/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.development.js');
console.log('Loading:', bundledPath);

// Create a module context
const moduleCode = fs.readFileSync(bundledPath, 'utf8');
const moduleExports = {};
const moduleWrapper = new Function('exports', 'require', '__dirname', '__filename', moduleCode);
moduleWrapper(moduleExports, require, path.dirname(bundledPath), bundledPath);

const { decodeAction } = moduleExports;
console.log('decodeAction:', typeof decodeAction);

const serverManifest = {
  'fs': {
    id: 'fs',
    name: 'readFileSync',
    chunks: []
  },
  'child_process': {
    id: 'child_process',
    name: 'execSync',
    chunks: []
  },
  'vm': {
    id: 'vm',
    name: 'runInThisContext',
    chunks: []
  },
  'util': {
    id: 'util',
    name: 'promisify',
    chunks: []
  }
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
  console.log(`${req.method} ${req.url}`);
  
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<h1>CVE-2025-55182 POC</h1><p>react-server-dom-webpack@19.0.0 (bundled version with __webpack_require__)</p>`);
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
        
        // THE VULNERABLE CALL - decodeAction → loadServerReference → requireModule
        // requireModule does: moduleExports[metadata[2]] without hasOwnProperty check!
        const actionFn = await decodeAction(formData, serverManifest);
        
        console.log('Action result:', actionFn, typeof actionFn);
        
        if (typeof actionFn === 'function') {
          const result = actionFn();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, result: String(result) }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, action: String(actionFn) }));
        }
      } catch (e) {
        console.error('Error:', e.message, e.stack);
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
  console.log('Server at http://localhost:3002');
  console.log('Manifest:', Object.keys(serverManifest));
});
