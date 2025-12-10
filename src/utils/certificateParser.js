import { parseCertificateFileWasm, buildCertificateChainWasm, generateNginxFormatWasm } from './wasmWrapper.js';

/**
 * Parse certificate files and extract certificate information using WASM backend
 */

// Extract certificate information for display
// This function now works with WASM-parsed certificate info
export function extractCertificateInfo(certInfo) {
  // If it's already processed by WASM, just return it
  if (certInfo.subject_common_name) {
    return {
      subject: JSON.parse(certInfo.subject || '{}'),
      issuer: JSON.parse(certInfo.issuer || '{}'),
      serialNumber: certInfo.serial_number,
      validFrom: new Date(certInfo.valid_from),
      validTo: new Date(certInfo.valid_to),
      subjectCommonName: certInfo.subject_common_name,
      issuerCommonName: certInfo.issuer_common_name,
      isCA: certInfo.is_ca,
      isSelfSigned: certInfo.is_self_signed,
    };
  }
  
  // Fallback for old format (shouldn't be needed but keeps compatibility)
  return certInfo;
}

// Main function to parse any certificate file using WASM
export async function parseCertificateFile(file, password = null) {
  try {
    const result = await parseCertificateFileWasm(file, password);
    
    if (result.error && result.error !== 'PKCS#12 parsing not fully implemented yet') {
      throw new Error(result.error);
    }
    
    // Transform WASM result to match expected format
    const certificates = result.certificates.map(cert => ({
      type: 'certificate',
      data: cert.info, // WASM provides parsed info directly
      pem: cert.pem,
    }));
    
    const privateKeys = result.privateKeys.map(key => ({
      type: 'privateKey',
      pem: key.pem,
      encrypted: key.encrypted,
    }));
    
    return {
      certificates,
      privateKeys,
      needsPassword: result.needsPassword,
    };
  } catch (error) {
    console.error('Error parsing certificate:', error);
    throw error;
  }
}

// Build certificate chain using WASM
export function buildCertificateChain(certificates) {
  // Extract certificate info if not already extracted
  const certInfos = certificates.map(cert => {
    const info = cert.info || extractCertificateInfo(cert.data);
    return info;
  });
  
  // Call WASM function
  const chains = buildCertificateChainWasm(certInfos);
  
  // Handle null or empty chains
  if (!chains || chains.length === 0) {
    return [];
  }
  
  // Transform chain indices back to certificate objects
  return chains.map(chain => 
    chain.map(index => ({
      cert: certificates[index].data,
      info: certInfos[index],
      wrapper: certificates[index],
    }))
  );
}

// Generate nginx-ready certificate format using WASM
export function generateNginxFormat(chain, privateKey) {
  const chainIndices = chain.map((_, index) => index);
  const pems = chain.map(certInfo => certInfo.wrapper.pem);
  const privateKeyPem = privateKey ? privateKey.pem : null;
  
  return generateNginxFormatWasm(chainIndices, pems, privateKeyPem);
}
