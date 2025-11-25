import forge from 'node-forge';
import fs from 'fs';

const pemData = fs.readFileSync('/tmp/google-cert.pem', 'utf8');

console.log('Testing deeper certificate parsing...\n');

// Get first certificate
const firstCert = pemData.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0];
const pemBlock = `-----BEGIN CERTIFICATE-----${firstCert}-----END CERTIFICATE-----`;

console.log('Trying certificateFromPem:', pemBlock.substring(0, 100));
try {
  const cert = forge.pki.certificateFromPem(pemBlock);
  console.log('✓ Success with certificateFromPem');
} catch (e) {
  console.log('✗ Failed with certificateFromPem:', e.message);
}

console.log('\nTrying certificateFromAsn1:');
try {
  const der = forge.util.decode64(firstCert.replace(/\s/g, ''));
  const asn1 = forge.asn1.fromDer(der);
  const cert = forge.pki.certificateFromAsn1(asn1, false); // Skip validation
  console.log('✓ Success with certificateFromAsn1 (no validation)');
  console.log('  Subject CN:', cert.subject.getField('CN')?.value);
} catch (e) {
  console.log('✗ Failed with certificateFromAsn1:', e.message);
}

console.log('\nTrying certificateFromAsn1 with validation:');
try {
  const der = forge.util.decode64(firstCert.replace(/\s/g, ''));
  const asn1 = forge.asn1.fromDer(der);
  const cert = forge.pki.certificateFromAsn1(asn1, true); // With validation
  console.log('✓ Success with certificateFromAsn1 (with validation)');
} catch (e) {
  console.log('✗ Failed with certificateFromAsn1 (with validation):', e.message);
}
