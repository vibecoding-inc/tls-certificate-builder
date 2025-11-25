/**
 * Tests for certificate parser
 * Run with: node tests/certificateParser.test.js
 */

import { parseCertificateFile, extractCertificateInfo, buildCertificateChain } from '../src/utils/certificateParser.js';
import { GOOGLE_ECDSA_CERT, RSA_CERT, CERT_CHAIN } from './test-certificates.js';

// Test helpers
let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`  ✗ FAILED: ${message}`);
    testsFailed++;
    throw new Error(message);
  }
}

function assertEquals(actual, expected, message) {
  if (actual !== expected) {
    console.error(`  ✗ FAILED: ${message}`);
    console.error(`    Expected: ${expected}`);
    console.error(`    Actual: ${actual}`);
    testsFailed++;
    throw new Error(message);
  }
}

function assertContains(str, substring, message) {
  if (!str || !str.includes(substring)) {
    console.error(`  ✗ FAILED: ${message}`);
    console.error(`    String does not contain: ${substring}`);
    console.error(`    Actual string: ${str}`);
    testsFailed++;
    throw new Error(message);
  }
}

async function test(name, fn) {
  process.stdout.write(`${name}... `);
  try {
    await fn();
    console.log('✓');
    testsPassed++;
  } catch (e) {
    testsFailed++;
    console.error(`Failed with error: ${e.message}`);
  }
}

// Mock FileReader for Node.js environment
function mockFileReader(content) {
  global.FileReader = class {
    readAsText() {
      setTimeout(() => {
        this.result = content;
        this.onload({ target: { result: content } });
      }, 0);
    }
    
    readAsArrayBuffer() {
      setTimeout(() => {
        const buffer = Buffer.from(content);
        this.result = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
        this.onload({ target: { result: this.result } });
      }, 0);
    }
  };
}

// Test suite
async function runTests() {
  console.log('\n=== Certificate Parser Tests ===\n');

  // Test 1: Parse ECDSA certificate (Google certificate)
  await test('Parse ECDSA certificate (Google)', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'google.pem', size: GOOGLE_ECDSA_CERT.length };
    const result = await parseCertificateFile(fakeFile);
    
    assert(result.certificates.length === 1, 'Should parse 1 certificate');
    
    const cert = result.certificates[0];
    assert(cert.type === 'certificate', 'Type should be certificate');
    assert(cert.data, 'Should have certificate data');
    assert(cert.pem, 'Should have PEM representation');
    
    // Check certificate fields
    const cn = cert.data.subject.getField('CN');
    assertEquals(cn?.value, 'www.google.com', 'Subject CN should be www.google.com');
    
    const issuerCn = cert.data.issuer.getField('CN');
    assertEquals(issuerCn?.value, 'WE2', 'Issuer CN should be WE2');
    
    assert(cert.data.serialNumber, 'Should have serial number');
    assert(cert.data.validity, 'Should have validity period');
    assert(cert.data.validity.notBefore, 'Should have notBefore date');
    assert(cert.data.validity.notAfter, 'Should have notAfter date');
  });

  // Test 2: Parse RSA certificate
  await test('Parse RSA certificate', async () => {
    mockFileReader(RSA_CERT);
    
    const fakeFile = { name: 'rsa.pem', size: RSA_CERT.length };
    const result = await parseCertificateFile(fakeFile);
    
    assert(result.certificates.length === 1, 'Should parse 1 certificate');
    
    const cert = result.certificates[0];
    assertEquals(cert.type, 'certificate', 'Type should be certificate');
    
    // RSA cert might not have CN, check if it exists or has other fields
    assert(cert.data.subject.attributes.length > 0, 'Should have subject attributes');
    assert(cert.data.issuer.attributes.length > 0, 'Should have issuer attributes');
  });

  // Test 3: Parse certificate chain
  await test('Parse certificate chain (multiple certs)', async () => {
    mockFileReader(CERT_CHAIN);
    
    const fakeFile = { name: 'chain.pem', size: CERT_CHAIN.length };
    const result = await parseCertificateFile(fakeFile);
    
    assertEquals(result.certificates.length, 3, 'Should parse 3 certificates from chain');
    
    // Check first cert (leaf)
    const leaf = result.certificates[0];
    const leafCn = leaf.data.subject.getField('CN');
    assertEquals(leafCn?.value, 'www.google.com', 'First cert should be www.google.com');
    
    // Check second cert (intermediate)
    const intermediate = result.certificates[1];
    const intermediateCn = intermediate.data.subject.getField('CN');
    assertEquals(intermediateCn?.value, 'WE2', 'Second cert should be WE2');
    
    // Check third cert (root)
    const root = result.certificates[2];
    const rootCn = root.data.subject.getField('CN');
    assertEquals(rootCn?.value, 'GTS Root R4', 'Third cert should be GTS Root R4');
  });

  // Test 4: Extract certificate info
  await test('Extract certificate info', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'google.pem', size: GOOGLE_ECDSA_CERT.length };
    const result = await parseCertificateFile(fakeFile);
    const cert = result.certificates[0].data;
    
    const info = extractCertificateInfo(cert);
    
    assert(info.subject, 'Should have subject info');
    assert(info.issuer, 'Should have issuer info');
    assertEquals(info.subjectCommonName, 'www.google.com', 'Subject CN should match');
    assertEquals(info.issuerCommonName, 'WE2', 'Issuer CN should match');
    assert(info.serialNumber, 'Should have serial number');
    assert(info.validFrom, 'Should have validFrom date');
    assert(info.validTo, 'Should have validTo date');
    assert(typeof info.isCA === 'boolean', 'isCA should be boolean');
    assert(typeof info.isSelfSigned === 'boolean', 'isSelfSigned should be boolean');
    assertEquals(info.isSelfSigned, false, 'Google cert should not be self-signed');
  });

  // Test 5: Build certificate chain
  await test('Build certificate chain', async () => {
    mockFileReader(CERT_CHAIN);
    
    const fakeFile = { name: 'chain.pem', size: CERT_CHAIN.length };
    const result = await parseCertificateFile(fakeFile);
    
    const chains = buildCertificateChain(result.certificates);
    
    assert(chains.length > 0, 'Should build at least one chain');
    assert(chains[0].length >= 1, 'Chain should have at least one certificate');
    
    // The leaf certificate should be first
    const firstInChain = chains[0][0];
    const cn = firstInChain.info.subjectCommonName;
    assertEquals(cn, 'www.google.com', 'First in chain should be leaf cert');
  });

  // Test 6: PEM format validation
  await test('PEM format is preserved', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'google.pem', size: GOOGLE_ECDSA_CERT.length };
    const result = await parseCertificateFile(fakeFile);
    
    const pem = result.certificates[0].pem;
    assertContains(pem, '-----BEGIN CERTIFICATE-----', 'PEM should have BEGIN marker');
    assertContains(pem, '-----END CERTIFICATE-----', 'PEM should have END marker');
    assert(pem.length > 100, 'PEM should have substantial content');
  });

  // Test 7: Handle different file extensions
  await test('Parse .pem file', async () => {
    mockFileReader(GOOGLE_ECDSA_CERT);
    
    const fakeFile = { name: 'cert.pem', size: GOOGLE_ECDSA_CERT.length };
    const result = await parseCertificateFile(fakeFile);
    
    assert(result.certificates.length === 1, 'Should parse certificate from .pem file');
  });

  // Print results
  console.log('\n=== Test Results ===');
  console.log(`Passed: ${testsPassed}`);
  console.log(`Failed: ${testsFailed}`);
  console.log(`Total: ${testsPassed + testsFailed}`);
  
  if (testsFailed > 0) {
    console.log('\n❌ Some tests failed');
    process.exit(1);
  } else {
    console.log('\n✅ All tests passed!');
    process.exit(0);
  }
}

// Run tests
runTests().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
