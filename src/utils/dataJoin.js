/**
 * Data join utilities for working with certificate and key data
 * Implements SQL-like INNER JOIN operations with ON and USING clauses
 */

/**
 * Perform an INNER JOIN on two arrays based on a condition function (ON clause)
 * @param {Array} leftArray - First array to join
 * @param {Array} rightArray - Second array to join
 * @param {Function} onCondition - Function that takes (leftItem, rightItem) and returns boolean
 * @returns {Array} Array of joined items { left, right }
 */
export function innerJoinOn(leftArray, rightArray, onCondition) {
  if (!Array.isArray(leftArray) || !Array.isArray(rightArray)) {
    throw new TypeError('Both arguments must be arrays');
  }
  
  if (typeof onCondition !== 'function') {
    throw new TypeError('onCondition must be a function');
  }

  const result = [];
  
  for (const leftItem of leftArray) {
    for (const rightItem of rightArray) {
      if (onCondition(leftItem, rightItem)) {
        result.push({ left: leftItem, right: rightItem });
      }
    }
  }
  
  return result;
}

/**
 * Perform an INNER JOIN on two arrays based on matching key(s) (USING clause)
 * @param {Array} leftArray - First array to join
 * @param {Array} rightArray - Second array to join
 * @param {string|Array<string>} keys - Key name(s) to match on
 * @returns {Array} Array of joined items { left, right }
 */
export function innerJoinUsing(leftArray, rightArray, keys) {
  if (!Array.isArray(leftArray) || !Array.isArray(rightArray)) {
    throw new TypeError('Both arguments must be arrays');
  }
  
  if (typeof keys === 'string') {
    keys = [keys];
  }
  
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new TypeError('keys must be a non-empty string or array of strings');
  }

  const result = [];
  
  for (const leftItem of leftArray) {
    for (const rightItem of rightArray) {
      let match = true;
      
      for (const key of keys) {
        if (leftItem[key] !== rightItem[key]) {
          match = false;
          break;
        }
      }
      
      if (match) {
        result.push({ left: leftItem, right: rightItem });
      }
    }
  }
  
  return result;
}

/**
 * Helper function to join certificates with private keys based on common name
 * This is a practical use case for certificate management
 * @param {Array} certificates - Array of certificate objects with info property
 * @param {Array} privateKeys - Array of private key objects
 * @returns {Array} Array of matched certificate-key pairs
 */
export function joinCertificatesWithKeys(certificates, privateKeys) {
  // Match by fileName
  return innerJoinUsing(
    certificates.map(c => ({ ...c, key: c.fileName })),
    privateKeys.map(k => ({ ...k, key: k.fileName })),
    'key'
  ).map(({ left, right }) => ({
    certificate: left,
    privateKey: right
  }));
}
