/**
 * Tests for certificate parser
 */

import { parseCertificateFile, extractCertificateInfo, buildCertificateChain } from '../src/utils/certificateParser.js';
import { GOOGLE_ECDSA_CERT, RSA_CERT, CERT_CHAIN } from './test-certificates.js';


// Mock FileReader for Node.js environment
class MockFileReader {
  constructor(content) {
    this.content = content;
    this.result = null;
    this.onload = null;
    this.onerror = null;
  }

  readAsText() {
    setTimeout(() => {
      this.result = this.content;
      if (this.onload) {
        this.onload({ target: { result: this.content } });
      }
    }, 0);
  }

  readAsArrayBuffer() {
    setTimeout(() => {
      const buffer = Buffer.from(this.content);
      this.result = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
      if (this.onload) {
        this.onload({ target: { result: this.result } });
      }
    }, 0);
  }
}

function mockFileReader(content) {
  global.FileReader = function() {
    const reader = new MockFileReader(content);
    return reader;
  };
}

describe('Certificate Parser Tests', () => {
  test('Parse ECDSA certificate (Google)', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'google.pem', size: GOOGLE_ECDSA_CERT.length, content: GOOGLE_ECDSA_CERT };
    const result = await parseCertificateFile(fakeFile);
    
    expect(result.certificates.length).toBe(1);
    
    const cert = result.certificates[0];
    expect(cert.type).toBe('certificate');
    expect(cert.data).toBeDefined();
    expect(cert.pem).toBeDefined();
    
    // Check certificate fields - WASM returns parsed info directly
    const info = extractCertificateInfo(cert.data);
    expect(info.subjectCommonName).toBe('www.google.com');
    expect(info.issuerCommonName).toBe('WE2');
    expect(info.serialNumber).toBeDefined();
    expect(info.validFrom).toBeDefined();
    expect(info.validTo).toBeDefined();
  });

  test('Parse RSA certificate', async () => {
    mockFileReader(RSA_CERT);
    
    const fakeFile = { name: 'rsa.pem', size: RSA_CERT.length, content: RSA_CERT };
    const result = await parseCertificateFile(fakeFile);
    
    expect(result.certificates.length).toBe(1);
    
    const cert = result.certificates[0];
    expect(cert.type).toBe('certificate');
    
    // WASM returns parsed info directly
    const info = extractCertificateInfo(cert.data);
    expect(info.subject).toBeDefined();
    expect(info.issuer).toBeDefined();
  });

  test('Parse certificate chain (multiple certs)', async () => {
    mockFileReader(CERT_CHAIN);
    
    const fakeFile = { name: 'chain.pem', size: CERT_CHAIN.length, content: CERT_CHAIN };
    const result = await parseCertificateFile(fakeFile);
    
    expect(result.certificates.length).toBe(3);
    
    // Check first cert (leaf)
    const leaf = result.certificates[0];
    const leafInfo = extractCertificateInfo(leaf.data);
    expect(leafInfo.subjectCommonName).toBe('www.google.com');
    
    // Check second cert (intermediate)
    const intermediate = result.certificates[1];
    const intermediateInfo = extractCertificateInfo(intermediate.data);
    expect(intermediateInfo.subjectCommonName).toBe('WE2');
    
    // Check third cert (root)
    const root = result.certificates[2];
    const rootInfo = extractCertificateInfo(root.data);
    expect(rootInfo.subjectCommonName).toBe('GTS Root R4');
  });

  test('Extract certificate info', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'google.pem', size: GOOGLE_ECDSA_CERT.length, content: GOOGLE_ECDSA_CERT };
    const result = await parseCertificateFile(fakeFile);
    const cert = result.certificates[0].data;
    
    const info = extractCertificateInfo(cert);
    
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

  test('Build certificate chain', async () => {
    mockFileReader(CERT_CHAIN);
    
    const fakeFile = { name: 'chain.pem', size: CERT_CHAIN.length, content: CERT_CHAIN };
    const result = await parseCertificateFile(fakeFile);
    
    const chains = buildCertificateChain(result.certificates);
    
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0].length).toBeGreaterThanOrEqual(1);
    
    // The leaf certificate should be first
    const firstInChain = chains[0][0];
    const cn = firstInChain.info.subjectCommonName;
    expect(cn).toBe('www.google.com');
  });

  test('PEM format is preserved', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'google.pem', size: GOOGLE_ECDSA_CERT.length, content: GOOGLE_ECDSA_CERT };
    const result = await parseCertificateFile(fakeFile);
    
    const pem = result.certificates[0].pem;
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
    expect(pem.length).toBeGreaterThan(100);
  });

  test('Parse .pem file', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'cert.pem', size: GOOGLE_ECDSA_CERT.length, content: GOOGLE_ECDSA_CERT };
    const result = await parseCertificateFile(fakeFile);
    
    expect(result.certificates.length).toBe(1);
  });
});
