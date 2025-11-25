import forge from 'node-forge';

/**
 * Parse certificate files and extract certificate information
 */

/**
 * Parse certificate from ASN.1 with support for non-RSA keys (EC, EdDSA, etc.)
 * This function manually extracts certificate information without relying on
 * node-forge's certificateFromAsn1 which only supports RSA keys.
 */
function safeCertificateFromAsn1(asn1) {
  // First try the standard method for RSA certificates
  try {
    return forge.pki.certificateFromAsn1(asn1);
  } catch (e) {
    // If it fails due to non-RSA key, parse manually
    if (!e.message || !e.message.includes('Cannot read public key')) {
      throw e;
    }
  }

  // Manual parsing for certificates with non-RSA keys
  // Certificate structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  const capture = {};
  const certSeq = asn1.value;
  
  if (!certSeq || certSeq.length < 3) {
    throw new Error('Invalid certificate structure');
  }

  const tbsCert = certSeq[0];
  let idx = 0;

  // Handle optional version field [0] EXPLICIT
  if (tbsCert.value[idx].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) {
    capture.certVersion = tbsCert.value[idx].value[0].value.charCodeAt(0);
    idx++;
  } else {
    capture.certVersion = 0; // Default version is v1 (0)
  }

  // Serial number
  capture.serialNumber = forge.util.createBuffer(tbsCert.value[idx++].value);

  // Signature algorithm
  capture.certSignatureOid = forge.asn1.derToOid(tbsCert.value[idx++].value[0].value);

  // Issuer
  capture.certIssuer = tbsCert.value[idx++];

  // Validity
  const validity = tbsCert.value[idx++];
  capture.certValidity = {
    notBefore: forge.asn1.utcTimeToDate(validity.value[0].value) || 
               forge.asn1.generalizedTimeToDate(validity.value[0].value),
    notAfter: forge.asn1.utcTimeToDate(validity.value[1].value) || 
              forge.asn1.generalizedTimeToDate(validity.value[1].value)
  };

  // Subject
  capture.certSubject = tbsCert.value[idx++];

  // SubjectPublicKeyInfo - we'll store it but not try to decode
  capture.certPublicKeyInfo = tbsCert.value[idx++];

  // Extensions (if present)
  if (idx < tbsCert.value.length && 
      tbsCert.value[idx].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC &&
      tbsCert.value[idx].type === 3) {
    capture.certExtensions = tbsCert.value[idx].value[0];
  }

  // Create certificate object manually
  const cert = {
    version: capture.certVersion + 1, // ASN.1 uses 0-based, display is 1-based
    serialNumber: forge.util.bytesToHex(capture.serialNumber.getBytes()),
    signatureOid: capture.certSignatureOid,
    signature: forge.util.createBuffer(certSeq[2].value),
    siginfo: {
      algorithmOid: forge.asn1.derToOid(certSeq[1].value[0].value)
    },
    validity: {
      notBefore: capture.certValidity.notBefore,
      notAfter: capture.certValidity.notAfter
    },
    issuer: {
      attributes: _parseRDNSequence(capture.certIssuer),
      getField: function(sn) {
        return this.attributes.find(attr => attr.shortName === sn || attr.name === sn);
      },
      hash: null
    },
    subject: {
      attributes: _parseRDNSequence(capture.certSubject),
      getField: function(sn) {
        return this.attributes.find(attr => attr.shortName === sn || attr.name === sn);
      },
      hash: null
    },
    extensions: capture.certExtensions ? _parseExtensions(capture.certExtensions) : [],
    publicKey: null, // We don't parse the public key for non-RSA certs
    md: null
  };

  return cert;
}

/**
 * Parse RDN (Relative Distinguished Name) sequence
 */
function _parseRDNSequence(rdn) {
  const attributes = [];
  
  for (const rdnSet of rdn.value) {
    for (const attrSeq of rdnSet.value) {
      const oid = forge.asn1.derToOid(attrSeq.value[0].value);
      const value = attrSeq.value[1].value;
      const attr = {
        type: oid,
        value: value,
        valueTagClass: attrSeq.value[1].type,
        name: forge.pki.oids[oid] || oid,
        shortName: _getShortName(oid)
      };
      attributes.push(attr);
    }
  }
  
  return attributes;
}

/**
 * Get short name for OID
 */
function _getShortName(oid) {
  const shortNames = {
    '2.5.4.3': 'CN',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.5': 'serialNumber',
    '1.2.840.113549.1.9.1': 'emailAddress'
  };
  return shortNames[oid] || forge.pki.oids[oid] || oid;
}

/**
 * Parse certificate extensions
 */
function _parseExtensions(extSeq) {
  const extensions = [];
  
  for (const extValue of extSeq.value) {
    const ext = {
      id: forge.asn1.derToOid(extValue.value[0].value),
      critical: false,
      value: null
    };
    
    let valueIdx = 1;
    if (extValue.value[1].type === forge.asn1.Type.BOOLEAN) {
      ext.critical = extValue.value[1].value.charCodeAt(0) !== 0;
      valueIdx = 2;
    }
    
    ext.value = extValue.value[valueIdx].value;
    ext.name = forge.pki.oids[ext.id] || ext.id;
    
    // Parse basic constraints for CA flag
    if (ext.id === '2.5.29.19' || ext.name === 'basicConstraints') {
      try {
        const bcAsn1 = forge.asn1.fromDer(ext.value);
        if (bcAsn1.value && bcAsn1.value.length > 0) {
          ext.cA = bcAsn1.value[0].type === forge.asn1.Type.BOOLEAN &&
                   bcAsn1.value[0].value.charCodeAt(0) !== 0;
        }
      } catch {
        // Ignore parsing errors for extensions
      }
    }
    
    extensions.push(ext);
  }
  
  return extensions;
}

/**
 * Safely convert certificate to PEM, handling non-RSA keys
 */
function safeCertificateToPem(asn1) {
  // For certificates with non-RSA keys, we need to convert the raw ASN.1 back to PEM
  // since certificateToPem won't work with our manually parsed certificate
  const der = forge.asn1.toDer(asn1);
  const pem = forge.util.encode64(der.getBytes(), 64);
  return '-----BEGIN CERTIFICATE-----\n' + pem + '\n-----END CERTIFICATE-----';
}

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
            // Extract the base64 content from PEM
            const pemContent = pemBlock
              .replace(/-----BEGIN CERTIFICATE-----/, '')
              .replace(/-----END CERTIFICATE-----/, '')
              .replace(/\s/g, '');
            const der = forge.util.decode64(pemContent);
            const asn1 = forge.asn1.fromDer(der);
            
            // Use safe parsing that handles non-RSA keys
            const cert = safeCertificateFromAsn1(asn1);
            
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
    const cert = safeCertificateFromAsn1(asn1);
    const pem = safeCertificateToPem(asn1);
    
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
          try {
            // Try standard PEM conversion
            const pem = forge.pki.certificateToPem(bag.cert);
            certificates.push({
              type: 'certificate',
              data: bag.cert,
              pem: pem,
            });
          } catch (e) {
            // For non-RSA certificates, convert from ASN.1
            if (bag.asn1) {
              const cert = safeCertificateFromAsn1(bag.asn1);
              const pem = safeCertificateToPem(bag.asn1);
              certificates.push({
                type: 'certificate',
                data: cert,
                pem: pem,
              });
            } else {
              console.warn('Failed to convert PKCS#12 certificate to PEM:', e);
            }
          }
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
        } else if (fileExtension === 'der') {
          // DER is always binary
          result = parseDER(e.target.result);
        } else if (fileExtension === 'crt' || fileExtension === 'cer') {
          // CRT/CER can be either DER or PEM
          // We read as ArrayBuffer, try DER first
          try {
            result = parseDER(e.target.result);
          } catch {
            // If DER fails, re-read as text and try PEM
            const textReader = new FileReader();
            textReader.onload = (te) => {
              result = parsePEM(te.target.result);
              resolve(result);
            };
            textReader.onerror = () => reject(new Error('Failed to read file as text'));
            textReader.readAsText(file);
            return;
          }
        } else {
          // Default to PEM (text-based) - file is already read as text
          result = parsePEM(e.target.result);
        }
        
        resolve(result);
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
