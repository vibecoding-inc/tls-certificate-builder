/**
 * Tests for data join utilities
 */

import { innerJoinOn, innerJoinUsing, joinCertificatesWithKeys } from '../src/utils/dataJoin.js';

describe('Data Join Tests', () => {
  describe('innerJoinOn', () => {
    test('should join two arrays with matching condition', () => {
      const left = [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' }
      ];
      const right = [
        { userId: 1, role: 'admin' },
        { userId: 2, role: 'user' }
      ];
      
      const result = innerJoinOn(left, right, (l, r) => l.id === r.userId);
      
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        left: { id: 1, name: 'Alice' },
        right: { userId: 1, role: 'admin' }
      });
      expect(result[1]).toEqual({
        left: { id: 2, name: 'Bob' },
        right: { userId: 2, role: 'user' }
      });
    });

    test('should return empty array when no matches', () => {
      const left = [{ id: 1 }];
      const right = [{ id: 2 }];
      
      const result = innerJoinOn(left, right, (l, r) => l.id === r.id);
      
      expect(result).toHaveLength(0);
    });

    test('should handle empty left array', () => {
      const left = [];
      const right = [{ id: 1 }];
      
      const result = innerJoinOn(left, right, (l, r) => l.id === r.id);
      
      expect(result).toHaveLength(0);
    });

    test('should handle empty right array', () => {
      const left = [{ id: 1 }];
      const right = [];
      
      const result = innerJoinOn(left, right, (l, r) => l.id === r.id);
      
      expect(result).toHaveLength(0);
    });

    test('should handle both arrays empty', () => {
      const result = innerJoinOn([], [], () => true);
      
      expect(result).toHaveLength(0);
    });

    test('should return multiple matches when condition matches multiple times', () => {
      const left = [
        { type: 'A', value: 1 },
        { type: 'A', value: 2 }
      ];
      const right = [
        { type: 'A', data: 'x' },
        { type: 'B', data: 'y' }
      ];
      
      const result = innerJoinOn(left, right, (l, r) => l.type === r.type);
      
      expect(result).toHaveLength(2);
      expect(result[0].left.value).toBe(1);
      expect(result[0].right.data).toBe('x');
      expect(result[1].left.value).toBe(2);
      expect(result[1].right.data).toBe('x');
    });

    test('should handle complex join conditions', () => {
      const left = [
        { start: 0, end: 10 },
        { start: 5, end: 15 }
      ];
      const right = [
        { value: 3 },
        { value: 7 },
        { value: 12 }
      ];
      
      const result = innerJoinOn(left, right, (l, r) => r.value >= l.start && r.value < l.end);
      
      // value 3 matches [0,10), value 7 matches both [0,10) and [5,15), value 12 matches [5,15)
      expect(result).toHaveLength(4);
    });

    test('should throw TypeError for non-array left argument', () => {
      expect(() => innerJoinOn(null, [], () => true)).toThrow(TypeError);
      expect(() => innerJoinOn(null, [], () => true)).toThrow('Both arguments must be arrays');
    });

    test('should throw TypeError for non-array right argument', () => {
      expect(() => innerJoinOn([], null, () => true)).toThrow(TypeError);
      expect(() => innerJoinOn([], null, () => true)).toThrow('Both arguments must be arrays');
    });

    test('should throw TypeError for non-function condition', () => {
      expect(() => innerJoinOn([], [], 'not a function')).toThrow(TypeError);
      expect(() => innerJoinOn([], [], 'not a function')).toThrow('onCondition must be a function');
    });

    test('should handle objects with nested properties', () => {
      const left = [
        { id: 1, details: { name: 'Alice' } }
      ];
      const right = [
        { refId: 1, status: 'active' }
      ];
      
      const result = innerJoinOn(left, right, (l, r) => l.id === r.refId);
      
      expect(result).toHaveLength(1);
      expect(result[0].left.details.name).toBe('Alice');
    });

    test('should preserve all properties of joined objects', () => {
      const left = [{ a: 1, b: 2, c: 3 }];
      const right = [{ x: 1, y: 2, z: 3 }];
      
      const result = innerJoinOn(left, right, (l, r) => l.a === r.x);
      
      expect(result[0].left).toEqual({ a: 1, b: 2, c: 3 });
      expect(result[0].right).toEqual({ x: 1, y: 2, z: 3 });
    });
  });

  describe('innerJoinUsing', () => {
    test('should join arrays using single key', () => {
      const left = [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' }
      ];
      const right = [
        { id: 1, role: 'admin' },
        { id: 2, role: 'user' }
      ];
      
      const result = innerJoinUsing(left, right, 'id');
      
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        left: { id: 1, name: 'Alice' },
        right: { id: 1, role: 'admin' }
      });
      expect(result[1]).toEqual({
        left: { id: 2, name: 'Bob' },
        right: { id: 2, role: 'user' }
      });
    });

    test('should join arrays using multiple keys', () => {
      const left = [
        { type: 'A', subtype: 'X', value: 1 },
        { type: 'A', subtype: 'Y', value: 2 },
        { type: 'B', subtype: 'X', value: 3 }
      ];
      const right = [
        { type: 'A', subtype: 'X', data: 'match1' },
        { type: 'A', subtype: 'Y', data: 'match2' },
        { type: 'B', subtype: 'Y', data: 'nomatch' }
      ];
      
      const result = innerJoinUsing(left, right, ['type', 'subtype']);
      
      expect(result).toHaveLength(2);
      expect(result[0].left.value).toBe(1);
      expect(result[0].right.data).toBe('match1');
      expect(result[1].left.value).toBe(2);
      expect(result[1].right.data).toBe('match2');
    });

    test('should return empty array when no key matches', () => {
      const left = [{ id: 1, name: 'Alice' }];
      const right = [{ id: 2, role: 'admin' }];
      
      const result = innerJoinUsing(left, right, 'id');
      
      expect(result).toHaveLength(0);
    });

    test('should handle empty arrays', () => {
      expect(innerJoinUsing([], [], 'id')).toHaveLength(0);
      expect(innerJoinUsing([{ id: 1 }], [], 'id')).toHaveLength(0);
      expect(innerJoinUsing([], [{ id: 1 }], 'id')).toHaveLength(0);
    });

    test('should handle multiple matches for same key', () => {
      const left = [
        { category: 'A', item: 'item1' },
        { category: 'A', item: 'item2' }
      ];
      const right = [
        { category: 'A', info: 'info1' }
      ];
      
      const result = innerJoinUsing(left, right, 'category');
      
      expect(result).toHaveLength(2);
      expect(result[0].left.item).toBe('item1');
      expect(result[1].left.item).toBe('item2');
    });

    test('should throw TypeError for non-array arguments', () => {
      expect(() => innerJoinUsing(null, [], 'id')).toThrow(TypeError);
      expect(() => innerJoinUsing([], null, 'id')).toThrow(TypeError);
    });

    test('should throw TypeError for invalid keys parameter', () => {
      expect(() => innerJoinUsing([], [], null)).toThrow(TypeError);
      expect(() => innerJoinUsing([], [], [])).toThrow(TypeError);
      expect(() => innerJoinUsing([], [], 123)).toThrow(TypeError);
    });

    test('should accept keys as array of strings', () => {
      const left = [{ a: 1, b: 2 }];
      const right = [{ a: 1, b: 2 }];
      
      const result = innerJoinUsing(left, right, ['a', 'b']);
      
      expect(result).toHaveLength(1);
    });

    test('should handle string key that does not exist in objects', () => {
      const left = [{ id: 1, name: 'Alice' }];
      const right = [{ id: 1, role: 'admin' }];
      
      const result = innerJoinUsing(left, right, 'nonexistent');
      
      // Both objects have undefined for 'nonexistent', so they match
      expect(result).toHaveLength(1);
    });

    test('should distinguish between null and undefined values', () => {
      const left = [
        { id: 1, value: null },
        { id: 2, value: undefined }
      ];
      const right = [
        { id: 1, value: null },
        { id: 2, value: undefined }
      ];
      
      const result = innerJoinUsing(left, right, ['id', 'value']);
      
      expect(result).toHaveLength(2);
    });

    test('should handle numeric keys', () => {
      const left = [{ id: 1, code: 100 }];
      const right = [{ id: 1, code: 100 }];
      
      const result = innerJoinUsing(left, right, 'code');
      
      expect(result).toHaveLength(1);
    });

    test('should handle boolean keys', () => {
      const left = [
        { id: 1, active: true },
        { id: 2, active: false }
      ];
      const right = [
        { id: 1, active: true },
        { id: 3, active: false }
      ];
      
      const result = innerJoinUsing(left, right, ['id', 'active']);
      
      expect(result).toHaveLength(1);
      expect(result[0].left.id).toBe(1);
    });

    test('should handle string keys', () => {
      const left = [
        { name: 'Alice', dept: 'Engineering' }
      ];
      const right = [
        { name: 'Alice', dept: 'Engineering' }
      ];
      
      const result = innerJoinUsing(left, right, ['name', 'dept']);
      
      expect(result).toHaveLength(1);
    });
  });

  describe('joinCertificatesWithKeys', () => {
    test('should join single certificate with single key when fileName matches', () => {
      const certs = [
        { fileName: 'cert.pem', info: { subjectCommonName: 'example.com' } }
      ];
      const keys = [
        { fileName: 'cert.pem', encrypted: false }
      ];
      
      const result = joinCertificatesWithKeys(certs, keys);
      
      expect(result).toHaveLength(1);
      expect(result[0].certificate.fileName).toBe('cert.pem');
      expect(result[0].privateKey.fileName).toBe('cert.pem');
    });

    test('should join certificates and keys by fileName', () => {
      const certs = [
        { fileName: 'server1.pem', info: { subjectCommonName: 'server1.com' } },
        { fileName: 'server2.pem', info: { subjectCommonName: 'server2.com' } }
      ];
      const keys = [
        { fileName: 'server1.pem', encrypted: false },
        { fileName: 'server2.pem', encrypted: false }
      ];
      
      const result = joinCertificatesWithKeys(certs, keys);
      
      expect(result).toHaveLength(2);
      expect(result[0].certificate.info.subjectCommonName).toBe('server1.com');
      expect(result[0].privateKey.fileName).toBe('server1.pem');
      expect(result[1].certificate.info.subjectCommonName).toBe('server2.com');
      expect(result[1].privateKey.fileName).toBe('server2.pem');
    });

    test('should return empty array when no matches', () => {
      const certs = [
        { fileName: 'cert1.pem', info: { subjectCommonName: 'example.com' } }
      ];
      const keys = [
        { fileName: 'cert2.pem', encrypted: false }
      ];
      
      const result = joinCertificatesWithKeys(certs, keys);
      
      expect(result).toHaveLength(0);
    });

    test('should handle empty arrays', () => {
      expect(joinCertificatesWithKeys([], [])).toHaveLength(0);
      expect(joinCertificatesWithKeys([{ fileName: 'cert.pem' }], [])).toHaveLength(0);
      expect(joinCertificatesWithKeys([], [{ fileName: 'key.pem' }])).toHaveLength(0);
    });

    test('should handle multiple certificates from same file', () => {
      const certs = [
        { fileName: 'bundle.pem', info: { subjectCommonName: 'cert1.com' } },
        { fileName: 'bundle.pem', info: { subjectCommonName: 'cert2.com' } }
      ];
      const keys = [
        { fileName: 'bundle.pem', encrypted: false }
      ];
      
      const result = joinCertificatesWithKeys(certs, keys);
      
      // Both certs match the same key file
      expect(result).toHaveLength(2);
    });

    test('should preserve certificate and key properties', () => {
      const certs = [
        { 
          fileName: 'cert.pem', 
          type: 'certificate',
          info: { 
            subjectCommonName: 'example.com',
            issuerCommonName: 'CA'
          },
          pem: '-----BEGIN CERTIFICATE-----'
        }
      ];
      const keys = [
        { 
          fileName: 'cert.pem', 
          type: 'privateKey',
          encrypted: false,
          pem: '-----BEGIN PRIVATE KEY-----'
        }
      ];
      
      const result = joinCertificatesWithKeys(certs, keys);
      
      expect(result).toHaveLength(1);
      expect(result[0].certificate.type).toBe('certificate');
      expect(result[0].certificate.info.subjectCommonName).toBe('example.com');
      expect(result[0].privateKey.type).toBe('privateKey');
      expect(result[0].privateKey.encrypted).toBe(false);
    });
  });

  describe('Integration tests', () => {
    test('innerJoinOn and innerJoinUsing should produce same results for equivalent conditions', () => {
      const left = [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' }
      ];
      const right = [
        { id: 1, role: 'admin' },
        { id: 2, role: 'user' }
      ];
      
      const resultOn = innerJoinOn(left, right, (l, r) => l.id === r.id);
      const resultUsing = innerJoinUsing(left, right, 'id');
      
      expect(resultOn).toEqual(resultUsing);
    });

    test('should handle large arrays efficiently', () => {
      const left = Array.from({ length: 100 }, (_, i) => ({ id: i, value: i * 2 }));
      const right = Array.from({ length: 50 }, (_, i) => ({ id: i * 2, data: `item${i}` }));
      
      const result = innerJoinUsing(left, right, 'id');
      
      expect(result).toHaveLength(50);
    });

    test('should handle special characters in string keys', () => {
      const left = [{ name: 'user@example.com', value: 1 }];
      const right = [{ name: 'user@example.com', data: 'test' }];
      
      const result = innerJoinUsing(left, right, 'name');
      
      expect(result).toHaveLength(1);
    });

    test('should handle whitespace in string values', () => {
      const left = [{ name: '  Alice  ', value: 1 }];
      const right = [{ name: '  Alice  ', data: 'test' }];
      
      const result = innerJoinUsing(left, right, 'name');
      
      expect(result).toHaveLength(1);
    });

    test('should not match trimmed vs non-trimmed strings', () => {
      const left = [{ name: 'Alice', value: 1 }];
      const right = [{ name: '  Alice  ', data: 'test' }];
      
      const result = innerJoinUsing(left, right, 'name');
      
      expect(result).toHaveLength(0);
    });
  });

  describe('Edge cases and error handling', () => {
    test('should handle objects with Symbol keys', () => {
      const sym = Symbol('test');
      const left = [{ [sym]: 'value1', id: 1 }];
      const right = [{ [sym]: 'value1', id: 1 }];
      
      // String key should still work
      const result = innerJoinUsing(left, right, 'id');
      expect(result).toHaveLength(1);
    });

    test('should handle arrays with mixed types', () => {
      const left = [
        { id: 1, value: 'string' },
        { id: '1', value: 'number' }
      ];
      const right = [
        { id: 1, data: 'numeric' },
        { id: '1', data: 'string' }
      ];
      
      const result = innerJoinUsing(left, right, 'id');
      
      // Strict equality - only exact type matches
      expect(result).toHaveLength(2);
      expect(result[0].left.value).toBe('string');
      expect(result[1].left.value).toBe('number');
    });

    test('should handle Date objects', () => {
      const date1 = new Date('2024-01-01');
      const date2 = new Date('2024-01-01');
      
      const left = [{ id: 1, date: date1 }];
      const right = [{ id: 1, date: date2 }];
      
      const result = innerJoinUsing(left, right, 'id');
      
      // Dates are different objects, but ids match
      expect(result).toHaveLength(1);
    });

    test('should handle NaN values', () => {
      const left = [{ id: 1, value: NaN }];
      const right = [{ id: 1, value: NaN }];
      
      const result = innerJoinUsing(left, right, ['id', 'value']);
      
      // NaN !== NaN, so this shouldn't match on value
      expect(result).toHaveLength(0);
    });

    test('should handle Infinity values', () => {
      const left = [{ id: 1, value: Infinity }];
      const right = [{ id: 1, value: Infinity }];
      
      const result = innerJoinUsing(left, right, ['id', 'value']);
      
      expect(result).toHaveLength(1);
    });
  });
});
