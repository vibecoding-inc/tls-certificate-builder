import init, * as wasm from '../../cert-parser-wasm/pkg/cert_parser_wasm.js';

let wasmInitialized = false;

// Initialize WASM module
async function ensureWasmInit() {
  if (!wasmInitialized) {
    await init();
    wasmInitialized = true;
  }
}

/**
 * Parse certificate files and extract certificate information
 */

// Main function to parse any certificate file
export async function parseCertificateFile(file, password = null) {
  await ensureWasmInit();
  
  const fileName = file.name.toLowerCase();
  const fileExtension = fileName.split('.').pop();
  
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = async (e) => {
      try {
        let result = { certificates: [], privateKeys: [], needsPassword: false };
        
        // Try different formats based on extension and content
        if (fileExtension === 'pfx' || fileExtension === 'p12') {
          // PKCS#12 not yet implemented in WASM
          // TODO: Implement PKCS#12 support in Rust WASM backend
          result.needsPassword = false;
          result.certificates = [];
          result.privateKeys = [];
          reject(new Error('PKCS#12 (.pfx/.p12) format is not yet supported in WASM backend'));
          return;
        } else if (fileExtension === 'der') {
          // DER is always binary
          const uint8Array = new Uint8Array(e.target.result);
          result = wasm.parse_der(uint8Array);
        } else if (fileExtension === 'crt' || fileExtension === 'cer') {
          // CRT/CER can be either DER or PEM
          try {
            const uint8Array = new Uint8Array(e.target.result);
            result = wasm.parse_der(uint8Array);
          } catch {
            // If DER fails, re-read as text and try PEM
            const textReader = new FileReader();
            textReader.onload = (te) => {
              try {
                result = wasm.parse_pem(te.target.result);
                
                // Process certificates and extract info
                const processed = processWasmResult(result, file.name);
                resolve(processed);
              } catch (err) {
                reject(err);
              }
            };
            textReader.onerror = () => reject(new Error('Failed to read file as text'));
            textReader.readAsText(file);
            return;
          }
        } else {
          // Default to PEM (text-based)
          result = wasm.parse_pem(e.target.result);
        }
        
        // Process certificates and extract info
        const processed = processWasmResult(result, file.name);
        resolve(processed);
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    
    // Read as ArrayBuffer only for binary formats
    if (fileExtension === 'pfx' || fileExtension === 'p12' || fileExtension === 'der') {
      reader.readAsArrayBuffer(file);
    } else if (fileExtension === 'crt' || fileExtension === 'cer') {
      // CRT/CER can be binary or text, try binary first
      reader.readAsArrayBuffer(file);
    } else {
      // Default to text for PEM and other text-based formats
      reader.readAsText(file);
    }
  });
}

function processWasmResult(result, fileName) {
  // The WASM result already has the info embedded in each certificate
  const certsWithInfo = result.certificates.map(cert => ({
    type: cert.type,
    data: cert, // Store the whole cert object as data
    pem: cert.pem,
    info: cert.info,
    fileName: fileName,
  }));

  return {
    certificates: certsWithInfo,
    privateKeys: result.privateKeys.map(key => ({
      ...key,
      fileName: fileName,
    })),
    needsPassword: result.needsPassword,
  };
}

// Extract certificate information for display
// This is now a pass-through since WASM already provides the info
export function extractCertificateInfo(cert) {
  // If cert has info, return it directly
  if (cert.info) {
    return cert.info;
  }
  
  // Otherwise, it's the info object itself
  return cert;
}

// Build certificate chain
export async function buildCertificateChain(certificates) {
  await ensureWasmInit();
  
  // Extract just the certificate data (which includes info)
  const certData = certificates.map(c => c.data || c);
  
  // Call WASM function
  const chainIndices = wasm.build_certificate_chain(certData);
  
  // Convert indices back to certificate chain objects
  const chains = chainIndices.map(indexChain => 
    indexChain.map(idx => {
      const cert = certificates[idx];
      return {
        cert: cert.data || cert,
        info: cert.info,
        wrapper: cert,
      };
    })
  );
  
  return chains;
}

// Generate nginx-ready certificate format
export async function generateNginxFormat(chain, privateKey) {
  await ensureWasmInit();
  
  // Extract certificate indices and data
  const chainIndices = chain.map((_, idx) => idx);
  const certData = chain.map(c => c.wrapper.data || c.wrapper);
  const privateKeyPem = privateKey?.pem || null;
  
  // Call WASM function
  return wasm.generate_nginx_format(chainIndices, certData, privateKeyPem);
}
