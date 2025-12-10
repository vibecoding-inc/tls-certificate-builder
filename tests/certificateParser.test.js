/**
 * Tests for certificate parser with WASM backend
 */

import { parsePEM, extractCertificateInfo, buildCertificateChain } from '../src/utils/certificateParser.js';
import { GOOGLE_ECDSA_CERT, RSA_CERT, CERT_CHAIN } from './test-certificates.js';

describe('Certificate Parser Tests (WASM)', () => {
  test('Parse ECDSA certificate (Google)', async () => {
    const result = await parsePEM(GOOGLE_ECDSA_CERT);
    
    expect(result.certificates.length).toBe(1);
    
    const cert = result.certificates[0];
    expect(cert.type).toBe('certificate');
    expect(cert.data).toBeDefined();
    expect(cert.pem).toBeDefined();
    expect(cert.info).toBeDefined();
    
    // Check certificate info fields from WASM
    expect(cert.info.subjectCommonName).toBe('www.google.com');
    expect(cert.info.issuerCommonName).toBe('WE2');
    expect(cert.info.serialNumber).toBeDefined();
    expect(cert.info.validFrom).toBeDefined();
    expect(cert.info.validTo).toBeDefined();
    expect(cert.info.isCA).toBe(false);
    expect(cert.info.isSelfSigned).toBe(false);
  });

  test('Parse RSA certificate', async () => {
    const result = await parsePEM(RSA_CERT);
    
    expect(result.certificates.length).toBe(1);
    
    const cert = result.certificates[0];
    expect(cert.type).toBe('certificate');
    expect(cert.info).toBeDefined();
    
    // RSA cert should have subject and issuer info
    expect(cert.info.subject).toBeDefined();
    expect(cert.info.issuer).toBeDefined();
    expect(cert.info.isCA).toBe(true); // This is a self-signed CA cert
    expect(cert.info.isSelfSigned).toBe(true);
  });

  test('Parse certificate chain (multiple certs)', async () => {
    const result = await parsePEM(CERT_CHAIN);
    
    expect(result.certificates.length).toBe(3);
    
    // Check first cert (leaf)
    const leaf = result.certificates[0];
    expect(leaf.info.subjectCommonName).toBe('www.google.com');
    expect(leaf.info.isCA).toBe(false);
    
    // Check second cert (intermediate)
    const intermediate = result.certificates[1];
    expect(intermediate.info.subjectCommonName).toBe('WE2');
    expect(intermediate.info.isCA).toBe(true);
    
    // Check third cert (root)
    const root = result.certificates[2];
    expect(root.info.subjectCommonName).toBe('GTS Root R4');
    expect(root.info.isCA).toBe(true);
    expect(root.info.isSelfSigned).toBe(true);
  });

  test('Extract certificate info', async () => {
    const result = await parsePEM(GOOGLE_ECDSA_CERT);
    const cert = result.certificates[0];
    
    const info = extractCertificateInfo(cert.data || cert);
    
    expect(info.subject).toBeDefined();
    expect(info.issuer).toBeDefined();
    expect(info.subjectCommonName).toBe('www.google.com');
    expect(info.issuerCommonName).toBe('WE2');
    expect(info.serialNumber).toBeDefined();
    expect(info.validFrom).toBeDefined();
    expect(info.validTo).toBeDefined();
    expect(typeof info.isCA).toBe('boolean');
    expect(typeof info.isSelfSigned).toBe('boolean');
    expect(info.isSelfSigned).toBe(false);
  });

  test('Build certificate chain from complete chain', async () => {
    const result = await parsePEM(CERT_CHAIN);
    
    const chains = await buildCertificateChain(result.certificates);
    
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].length).toBe(3); // Should have all 3 certs
    
    // The leaf certificate should be first
    const firstInChain = chains[0][0];
    expect(firstInChain.info.subjectCommonName).toBe('www.google.com');
    
    // Intermediate should be second
    const secondInChain = chains[0][1];
    expect(secondInChain.info.subjectCommonName).toBe('WE2');
    
    // Root should be third
    const thirdInChain = chains[0][2];
    expect(thirdInChain.info.subjectCommonName).toBe('GTS Root R4');
  });

  test('PEM format is preserved', async () => {
    const result = await parsePEM(GOOGLE_ECDSA_CERT);
    
    const pem = result.certificates[0].pem;
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
    expect(pem.length).toBeGreaterThan(100);
  });
  
  test('Reconstruct chain from separate leaf and intermediate certs', async () => {
    // Parse the chain to get individual certificates
    const chainResult = await parsePEM(CERT_CHAIN);
    expect(chainResult.certificates.length).toBe(3);
    
    // Take only leaf and intermediate (no root)
    const partialCerts = [
      chainResult.certificates[0], // leaf
      chainResult.certificates[1]  // intermediate
    ];
    
    const chains = await buildCertificateChain(partialCerts);
    
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].length).toBe(2);
    expect(chains[0][0].info.subjectCommonName).toBe('www.google.com');
    expect(chains[0][1].info.subjectCommonName).toBe('WE2');
  });
  
  test('Reconstruct chain from leaf only', async () => {
    const chainResult = await parsePEM(CERT_CHAIN);
    
    // Take only the leaf certificate
    const leafOnly = [chainResult.certificates[0]];
    
    const chains = await buildCertificateChain(leafOnly);
    
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].length).toBe(1);
    expect(chains[0][0].info.subjectCommonName).toBe('www.google.com');
  });
  
  test('Reconstruct chain from unordered certificates', async () => {
    const chainResult = await parsePEM(CERT_CHAIN);
    
    // Reverse the order (root, intermediate, leaf)
    const unordered = [
      chainResult.certificates[2], // root
      chainResult.certificates[0], // leaf  
      chainResult.certificates[1]  // intermediate
    ];
    
    const chains = await buildCertificateChain(unordered);
    
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].length).toBe(3);
    
    // Should still reconstruct in proper order (leaf -> intermediate -> root)
    expect(chains[0][0].info.subjectCommonName).toBe('www.google.com');
    expect(chains[0][1].info.subjectCommonName).toBe('WE2');
    expect(chains[0][2].info.subjectCommonName).toBe('GTS Root R4');
  });
  
  test('Handle multiple separate certificate chains', async () => {
    const googleChain = await parsePEM(CERT_CHAIN);
    const rsaCert = await parsePEM(RSA_CERT);
    
    // Mix two separate certificate chains
    const mixed = [
      ...googleChain.certificates,
      ...rsaCert.certificates
    ];
    
    const chains = await buildCertificateChain(mixed);
    
    // Should identify at least 1 chain (Google chain)
    // RSA cert is self-signed, so it may be treated as both leaf and root
    expect(chains.length).toBeGreaterThanOrEqual(1);
    expect(chains.length).toBeLessThanOrEqual(2);
  });

  test('Parse private key from PEM', async () => {
    // Use a valid test private key (this is a dummy key for testing)
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVcB/UNPxalR9zDYA
jQIyRVS13jbdeEzIM3/Bwg5DxZqhRANCAATehB5dEJhg7gXHaC+vZN2VBfjKpXYj
xKSBCT/t/r9RbpgJt8MaYkPKNEXtDLNQJQYy+7pqf9XWNNDEcqR1rJxL
-----END PRIVATE KEY-----`;
    
    const result = await parsePEM(privateKeyPem);
    
    expect(result.privateKeys.length).toBe(1);
    expect(result.privateKeys[0].type).toBe('privateKey');
    expect(result.privateKeys[0].pem).toBeDefined();
  });

  test('Parse mixed certificate and private key', async () => {
    const mixed = `${GOOGLE_ECDSA_CERT}
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVcB/UNPxalR9zDYA
jQIyRVS13jbdeEzIM3/Bwg5DxZqhRANCAATehB5dEJhg7gXHaC+vZN2VBfjKpXYj
xKSBCT/t/r9RbpgJt8MaYkPKNEXtDLNQJQYy+7pqf9XWNNDEcqR1rJxL
-----END PRIVATE KEY-----`;
    
    const result = await parsePEM(mixed);
    
    expect(result.certificates.length).toBe(1);
    expect(result.privateKeys.length).toBe(1);
  });
});
