import forge from 'node-forge';

/**
 * Parse certificate files and extract certificate information
 */

// Try to parse PEM format
function parsePEM(data) {
  const certificates = [];
  const privateKeys = [];
  
  try {
    // Try to parse as PEM
    const lines = data.split('\n');
    let currentBlock = [];
    let inBlock = false;
    let blockType = null;

    for (const line of lines) {
      const trimmed = line.trim();
      
      if (trimmed.startsWith('-----BEGIN')) {
        inBlock = true;
        blockType = trimmed;
        currentBlock = [line];
      } else if (trimmed.startsWith('-----END')) {
        currentBlock.push(line);
        inBlock = false;
        
        const pemBlock = currentBlock.join('\n');
        
        if (blockType.includes('CERTIFICATE')) {
          try {
            const cert = forge.pki.certificateFromPem(pemBlock);
            certificates.push({
              type: 'certificate',
              data: cert,
              pem: pemBlock,
            });
          } catch (e) {
            console.warn('Failed to parse certificate:', e);
          }
        } else if (blockType.includes('PRIVATE KEY') || blockType.includes('RSA PRIVATE KEY')) {
          privateKeys.push({
            type: 'privateKey',
            pem: pemBlock,
            encrypted: blockType.includes('ENCRYPTED'),
          });
        }
        
        currentBlock = [];
        blockType = null;
      } else if (inBlock) {
        currentBlock.push(line);
      }
    }
  } catch (e) {
    console.error('Error parsing PEM:', e);
  }

  return { certificates, privateKeys };
}

// Try to parse DER format
function parseDER(arrayBuffer) {
  const certificates = [];
  
  try {
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(arrayBuffer));
    const cert = forge.pki.certificateFromAsn1(asn1);
    const pem = forge.pki.certificateToPem(cert);
    
    certificates.push({
      type: 'certificate',
      data: cert,
      pem: pem,
    });
  } catch (e) {
    console.warn('Not a DER certificate:', e);
  }

  return { certificates, privateKeys: [] };
}

// Try to parse PKCS#12/PFX format
async function parsePKCS12(arrayBuffer, password = '') {
  const certificates = [];
  const privateKeys = [];
  
  try {
    const p12Der = forge.util.createBuffer(arrayBuffer);
    const p12Asn1 = forge.asn1.fromDer(p12Der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

    // Extract certificates
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    for (const bagType in certBags) {
      for (const bag of certBags[bagType]) {
        if (bag.cert) {
          const pem = forge.pki.certificateToPem(bag.cert);
          certificates.push({
            type: 'certificate',
            data: bag.cert,
            pem: pem,
          });
        }
      }
    }

    // Extract private keys
    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    for (const bagType in keyBags) {
      for (const bag of keyBags[bagType]) {
        if (bag.key) {
          const pem = forge.pki.privateKeyToPem(bag.key);
          privateKeys.push({
            type: 'privateKey',
            pem: pem,
            encrypted: false,
          });
        }
      }
    }

    // Also check for unencrypted key bags
    const unencryptedKeyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
    for (const bagType in unencryptedKeyBags) {
      for (const bag of unencryptedKeyBags[bagType]) {
        if (bag.key) {
          const pem = forge.pki.privateKeyToPem(bag.key);
          privateKeys.push({
            type: 'privateKey',
            pem: pem,
            encrypted: false,
          });
        }
      }
    }
  } catch (e) {
    if (e.message && e.message.includes('Invalid password')) {
      throw new Error('INVALID_PASSWORD');
    }
    throw e;
  }

  return { certificates, privateKeys };
}

// Extract certificate information for display
export function extractCertificateInfo(cert) {
  const subject = cert.subject.attributes.reduce((acc, attr) => {
    acc[attr.shortName || attr.name] = attr.value;
    return acc;
  }, {});

  const issuer = cert.issuer.attributes.reduce((acc, attr) => {
    acc[attr.shortName || attr.name] = attr.value;
    return acc;
  }, {});

  return {
    subject,
    issuer,
    serialNumber: cert.serialNumber,
    validFrom: cert.validity.notBefore,
    validTo: cert.validity.notAfter,
    subjectCommonName: subject.CN || 'Unknown',
    issuerCommonName: issuer.CN || 'Unknown',
    isCA: cert.extensions.some(ext => 
      ext.name === 'basicConstraints' && ext.cA === true
    ),
    isSelfSigned: JSON.stringify(subject) === JSON.stringify(issuer),
  };
}

// Main function to parse any certificate file
export async function parseCertificateFile(file, password = null) {
  const fileName = file.name.toLowerCase();
  const fileExtension = fileName.split('.').pop();
  
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = async (e) => {
      try {
        let result = { certificates: [], privateKeys: [], needsPassword: false };
        
        // Try different formats based on extension and content
        if (fileExtension === 'pfx' || fileExtension === 'p12') {
          try {
            result = await parsePKCS12(e.target.result, password || '');
          } catch (error) {
            if (error.message === 'INVALID_PASSWORD') {
              result.needsPassword = true;
            } else {
              throw error;
            }
          }
        } else if (fileExtension === 'der' || fileExtension === 'crt' || fileExtension === 'cer') {
          // Try DER first
          try {
            result = parseDER(e.target.result);
          } catch {
            // If DER fails, try PEM (read as text)
            const textReader = new FileReader();
            textReader.onload = (te) => {
              result = parsePEM(te.target.result);
              resolve(result);
            };
            textReader.readAsText(file);
            return;
          }
        } else {
          // Default to PEM (text-based)
          const textData = new TextDecoder().decode(e.target.result);
          result = parsePEM(textData);
        }
        
        resolve(result);
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    
    // Read as ArrayBuffer for binary formats
    if (fileExtension === 'pfx' || fileExtension === 'p12' || 
        fileExtension === 'der' || fileExtension === 'crt' || fileExtension === 'cer') {
      reader.readAsArrayBuffer(file);
    } else {
      reader.readAsText(file);
    }
  });
}

// Build certificate chain
export function buildCertificateChain(certificates) {
  const chain = [];
  const certMap = new Map();
  
  // Create a map of certificates by subject
  certificates.forEach((certWrapper, index) => {
    const cert = certWrapper.data;
    const info = extractCertificateInfo(cert);
    certMap.set(index, { cert, info, wrapper: certWrapper });
  });

  // Find leaf certificates (non-CA or end-entity certs)
  const leaves = [];
  certMap.forEach((value, key) => {
    if (!value.info.isCA || value.info.isSelfSigned) {
      leaves.push(key);
    }
  });

  // For each leaf, try to build a chain
  leaves.forEach(leafKey => {
    const chainForLeaf = [];
    let current = certMap.get(leafKey);
    const visited = new Set();
    
    while (current && !visited.has(current)) {
      visited.add(current);
      chainForLeaf.push(current);
      
      // Find issuer
      if (current.info.isSelfSigned) {
        break; // Reached root
      }
      
      let found = false;
      certMap.forEach((value) => {
        if (!found && !visited.has(value) && 
            value.info.subjectCommonName === current.info.issuerCommonName) {
          current = value;
          found = true;
        }
      });
      
      if (!found) {
        break; // Can't find issuer
      }
    }
    
    if (chainForLeaf.length > 0) {
      chain.push(chainForLeaf);
    }
  });

  return chain;
}

// Generate nginx-ready certificate format
export function generateNginxFormat(chain, privateKey) {
  let output = '';
  
  // Add certificates in order (leaf to root)
  chain.forEach(certInfo => {
    output += certInfo.wrapper.pem + '\n';
  });
  
  // Add private key if available
  if (privateKey) {
    output += '\n' + privateKey.pem;
  }
  
  return output.trim();
}
