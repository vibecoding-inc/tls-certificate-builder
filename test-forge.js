const forge = require('node-forge');
const fs = require('fs');

const pemData = fs.readFileSync('/tmp/google-cert.pem', 'utf8');

console.log('Testing certificate parsing with node-forge...\n');

// Split the PEM into individual certificates
const lines = pemData.split('\n');
let currentBlock = [];
let inBlock = false;
let blockType = null;
let certCount = 0;

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
      certCount++;
      console.log(`\nCertificate ${certCount}:`);
      
      try {
        const cert = forge.pki.certificateFromPem(pemBlock);
        console.log(`✓ Successfully parsed`);
        console.log(`  Subject CN: ${cert.subject.getField('CN')?.value || 'N/A'}`);
      } catch (e) {
        console.log(`✗ Failed to parse`);
        console.log(`  Error: ${e.message}`);
      }
    }
    
    currentBlock = [];
    blockType = null;
  } else if (inBlock) {
    currentBlock.push(line);
  }
}
