/**
 * JavaScript wrapper for the WASM certificate parser
 * This provides a bridge between the Rust WASM module and the existing JavaScript API
 */

import init, {
  parse_certificate_file,
  build_certificate_chain,
  generate_nginx_format,
} from '../../pkg/cert_wasm.js';
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

let wasmInitialized = false;

/**
 * Initialize the WASM module
 */
export async function initWasm() {
  if (!wasmInitialized) {
    // Check if we're in Node.js environment
    if (typeof process !== 'undefined' && process.versions && process.versions.node) {
      // Node.js environment - load WASM file directly
      try {
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = dirname(__filename);
        const wasmPath = join(__dirname, '../../pkg/cert_wasm_bg.wasm');
        const wasmBuffer = await readFile(wasmPath);
        await init(wasmBuffer);
      } catch (error) {
        console.error('Failed to load WASM in Node.js:', error);
        throw error;
      }
    } else {
      // Browser environment - use default init
      await init();
    }
    wasmInitialized = true;
  }
}

/**
 * Parse certificate file using WASM
 * @param {File|Object} file - The file to parse (or mock object with name and arrayBuffer method)
 * @param {string|null} password - Optional password for encrypted files
 * @returns {Promise<{certificates: Array, privateKeys: Array, needsPassword: boolean}>}
 */
export async function parseCertificateFileWasm(file, password = null) {
  await initWasm();

  // Read file as ArrayBuffer
  let arrayBuffer;
  if (file.arrayBuffer) {
    arrayBuffer = await file.arrayBuffer();
  } else if (file.content) {
    // Test mock object with content
    const buffer = Buffer.from(file.content);
    arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  } else {
    throw new Error('File object must have either arrayBuffer() method or content property');
  }
  
  const uint8Array = new Uint8Array(arrayBuffer);

  // Call WASM function
  const result = parse_certificate_file(uint8Array, file.name, password);

  return {
    certificates: result.certificates || [],
    privateKeys: result.private_keys || [],
    needsPassword: result.needs_password || false,
    error: result.error || null,
  };
}

/**
 * Build certificate chain using WASM
 * @param {Array} certificates - Array of certificate info objects
 * @returns {Array<Array<number>>} Array of chains (each chain is an array of indices)
 */
export function buildCertificateChainWasm(certificates) {
  return build_certificate_chain(certificates);
}

/**
 * Generate nginx format using WASM
 * @param {Array<number>} chainIndices - Array of certificate indices in the chain
 * @param {Array<string>} pems - Array of PEM strings
 * @param {string|null} privateKeyPem - Optional private key PEM
 * @returns {string} Nginx-formatted certificate chain
 */
export function generateNginxFormatWasm(chainIndices, pems, privateKeyPem = null) {
  return generate_nginx_format(chainIndices, pems, privateKeyPem);
}
