/**
 * Pure Functions Tests - Serverless Ready Operations
 * 
 * Tests all pure encoding/decoding functions with edge cases
 * and concurrent execution validation
 */

import { describe, it, expect } from 'vitest';
import {
  encode,
  decode,
  encodeBase64,
  decodeBase64,
  encodeBase64URL,
  decodeBase64URL,
  encodeHex,
  decodeHex,
  encodeURIString,
  decodeURIString,
  encodeASCII,
  decodeASCII,
  detectFormat,
  validateFormat,
  chain,
  reverseChain,
  type EncodingFormat
} from '../src/functions.js';

describe('Pure Functions - Core Operations', () => {
  describe('Base64 Functions', () => {
    it('should encode/decode base64 correctly', () => {
      const text = 'Hello World';
      const encoded = encodeBase64(text);
      expect(encoded).toBe('SGVsbG8gV29ybGQ=');
      
      const decoded = decodeBase64(encoded);
      expect(decoded).toBe(text);
    });

    it('should handle empty strings', () => {
      expect(encodeBase64('')).toBe('');
      expect(decodeBase64('')).toBe('');
    });

    it('should handle unicode characters', () => {
      const unicode = '🚀 Hello 世界';
      const encoded = encodeBase64(unicode);
      const decoded = decodeBase64(encoded);
      expect(decoded).toBe(unicode);
    });

    it('should be reversible for all printable ASCII', () => {
      const ascii = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
      const encoded = encodeBase64(ascii);
      const decoded = decodeBase64(encoded);
      expect(decoded).toBe(ascii);
    });
  });

  describe('Base64URL Functions', () => {
    it('should encode/decode base64url correctly', () => {
      const text = 'Hello World!';
      const encoded = encodeBase64URL(text);
      expect(encoded).toBe('SGVsbG8gV29ybGQh');
      expect(encoded).not.toContain('=');
      
      const decoded = decodeBase64URL(encoded);
      expect(decoded).toBe(text);
    });

    it('should produce URL-safe output', () => {
      const text = 'Hello+World/Test=';
      const encoded = encodeBase64URL(text);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
      
      const decoded = decodeBase64URL(encoded);
      expect(decoded).toBe(text);
    });

    it('should handle padding correctly', () => {
      const tests = ['A', 'AB', 'ABC', 'ABCD'];
      
      for (const test of tests) {
        const encoded = encodeBase64URL(test);
        const decoded = decodeBase64URL(encoded);
        expect(decoded).toBe(test);
      }
    });
  });

  describe('Hexadecimal Functions', () => {
    it('should encode/decode hex correctly', () => {
      const text = 'Hello';
      const encoded = encodeHex(text);
      expect(encoded).toBe('48656c6c6f');
      
      const decoded = decodeHex(encoded);
      expect(decoded).toBe(text);
    });

    it('should handle mixed case hex decoding', () => {
      expect(decodeHex('48656c6c6f')).toBe('Hello');
      expect(decodeHex('48656C6C6F')).toBe('Hello');
      expect(decodeHex('48656c6C6f')).toBe('Hello');
    });

    it('should throw on invalid hex', () => {
      expect(() => decodeHex('48656c6c6g')).toThrow('contains non-hex characters');
      expect(() => decodeHex('48656c6c6')).toThrow('length must be even');
    });

    it('should handle control characters', () => {
      const text = '\x00\x01\x02\x1f\x7f';
      const encoded = encodeHex(text);
      const decoded = decodeHex(encoded);
      expect(decoded).toBe(text);
    });
  });

  describe('URI Functions', () => {
    it('should encode/decode URI correctly', () => {
      const text = 'Hello World!';
      const encoded = encodeURIString(text);
      expect(encoded).toBe('Hello%20World!');
      
      const decoded = decodeURIString(encoded);
      expect(decoded).toBe(text);
    });

    it('should handle special characters', () => {
      const special = 'test@example.com?param=value&other=test#anchor';
      const encoded = encodeURIString(special);
      const decoded = decodeURIString(encoded);
      expect(decoded).toBe(special);
    });

    it('should handle unicode in URIs', () => {
      const unicode = 'Hello 世界';
      const encoded = encodeURIString(unicode);
      const decoded = decodeURIString(encoded);
      expect(decoded).toBe(unicode);
    });
  });

  describe('ASCII Functions', () => {
    it('should encode ASCII text unchanged', () => {
      const text = 'Hello World';
      const encoded = encodeASCII(text);
      expect(encoded).toBe(text);
    });

    it('should throw on non-ASCII characters', () => {
      expect(() => encodeASCII('Hello 世界')).toThrow('Non-ASCII character found');
      expect(() => encodeASCII('Hello\u0080')).toThrow('Non-ASCII character found');
    });

    it('should validate printable ASCII on decode', () => {
      expect(decodeASCII('Hello World')).toBe('Hello World');
      expect(() => decodeASCII('Hello\x00World')).toThrow('Non-printable ASCII');
      expect(() => decodeASCII('Hello\x1fWorld')).toThrow('Non-printable ASCII');
    });

    it('should handle all printable ASCII characters', () => {
      const printable = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
      expect(encodeASCII(printable)).toBe(printable);
      expect(decodeASCII(printable)).toBe(printable);
    });
  });
});

describe('Pure Functions - Generic Operations', () => {
  describe('Generic Encode/Decode', () => {
    const testData = 'Hello World';
    const formats: EncodingFormat[] = ['base64', 'base64url', 'hex', 'uri', 'ascii'];

    it('should encode to all formats', () => {
      for (const format of formats) {
        const encoded = encode(testData, format);
        expect(typeof encoded).toBe('string');
        expect(encoded.length).toBeGreaterThan(0);
      }
    });

    it('should decode from all formats', () => {
      for (const format of formats) {
        const encoded = encode(testData, format);
        const decoded = decode(encoded, format);
        expect(decoded).toBe(testData);
      }
    });

    it('should throw on unknown formats', () => {
      expect(() => encode('test', 'unknown' as EncodingFormat)).toThrow('Unsupported encoding format');
      expect(() => decode('test', 'unknown' as EncodingFormat)).toThrow('Unsupported decoding format');
    });
  });

  describe('Format Detection', () => {
    it('should detect base64', () => {
      expect(detectFormat('SGVsbG8gV29ybGQ=')).toBe('base64');
      expect(detectFormat('QQ==')).toBe('base64');
    });

    it('should detect base64url', () => {
      expect(detectFormat('SGVsbG8gV29ybGQh')).toBe('base64url');
      expect(detectFormat('QQ')).toBe('base64url');
    });

    it('should detect hex', () => {
      expect(detectFormat('48656c6c6f')).toBe('hex');
      expect(detectFormat('DEADBEEF')).toBe('hex');
    });

    it('should detect URI encoding', () => {
      expect(detectFormat('Hello%20World')).toBe('uri');
      expect(detectFormat('test%21%40%23')).toBe('uri');
    });

    it('should detect ASCII', () => {
      expect(detectFormat('Hello World')).toBe('ascii');
      expect(detectFormat('Plain text')).toBe('ascii');
    });

    it('should throw for undetectable data', () => {
      expect(() => detectFormat('🚀💫🌟')).toThrow('Cannot detect encoding format');
      expect(() => detectFormat('\x00\x01\x02')).toThrow('Cannot detect encoding format');
    });
  });

  describe('Format Validation', () => {
    it('should validate correct formats', () => {
      expect(validateFormat('SGVsbG8gV29ybGQ=', 'base64')).toBe(true);
      expect(validateFormat('SGVsbG8gV29ybGQh', 'base64url')).toBe(true);
      expect(validateFormat('48656c6c6f', 'hex')).toBe(true);
      expect(validateFormat('Hello%20World', 'uri')).toBe(true);
      expect(validateFormat('Hello World', 'ascii')).toBe(true);
    });

    it('should invalidate incorrect formats', () => {
      expect(validateFormat('SGVsbG8gV29ybGQ', 'base64')).toBe(false); // missing padding
      expect(validateFormat('SGVsbG8+V29ybGQ=', 'base64url')).toBe(false); // contains +
      expect(validateFormat('48656c6c6g', 'hex')).toBe(false); // invalid char
      expect(validateFormat('Hello%', 'uri')).toBe(false); // incomplete encoding
      expect(validateFormat('Hello 世界', 'ascii')).toBe(false); // non-ASCII
    });
  });
});

describe('Pure Functions - Advanced Operations', () => {
  describe('Chain Operations', () => {
    it('should chain encodings correctly', () => {
      const original = 'Hello';
      
      // Chain: Hello -> hex -> base64
      const chained = chain(original, ['hex', 'base64']);
      expect(chained).toBe('NDg2NTZjNmM2Zg==');
      
      // Verify by manual steps
      const step1 = encodeHex(original); // '48656c6c6f'
      const step2 = encodeBase64(step1); // 'NDg2NTZjNmM2Zg=='
      expect(chained).toBe(step2);
    });

    it('should reverse chain correctly', () => {
      const original = 'Hello World';
      const formats: EncodingFormat[] = ['hex', 'base64', 'uri'];
      
      const chained = chain(original, formats);
      const reversed = reverseChain(chained, formats);
      
      expect(reversed).toBe(original);
    });

    it('should handle single operation chains', () => {
      const original = 'Hello';
      const chained = chain(original, ['base64']);
      const reversed = reverseChain(chained, ['base64']);
      
      expect(reversed).toBe(original);
    });

    it('should handle empty chains', () => {
      const original = 'Hello';
      const chained = chain(original, []);
      const reversed = reverseChain(original, []);
      
      expect(chained).toBe(original);
      expect(reversed).toBe(original);
    });

    it('should propagate errors in chains', () => {
      expect(() => chain('Hello 世界', ['ascii', 'base64'])).toThrow('Non-ASCII character found');
      expect(() => reverseChain('invalid', ['base64', 'hex'])).toThrow();
    });
  });

  describe('Edge Cases & Error Handling', () => {
    it('should handle very long strings', () => {
      const longString = 'A'.repeat(10000);
      const encoded = encodeBase64(longString);
      const decoded = decodeBase64(encoded);
      expect(decoded).toBe(longString);
    });

    it('should handle special characters in all formats', () => {
      const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      
      const base64Encoded = encodeBase64(special);
      expect(decodeBase64(base64Encoded)).toBe(special);
      
      const hexEncoded = encodeHex(special);
      expect(decodeHex(hexEncoded)).toBe(special);
      
      const uriEncoded = encodeURIString(special);
      expect(decodeURIString(uriEncoded)).toBe(special);
    });

    it('should handle binary data correctly', () => {
      // Simulate binary data as string with control characters
      const binaryLike = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f';
      
      const base64Encoded = encodeBase64(binaryLike);
      expect(decodeBase64(base64Encoded)).toBe(binaryLike);
      
      const hexEncoded = encodeHex(binaryLike);
      expect(decodeHex(hexEncoded)).toBe(binaryLike);
    });

    it('should preserve exact byte sequences', () => {
      // Test all possible byte values (0-255) as string
      const allBytes = Array.from({ length: 256 }, (_, i) => String.fromCharCode(i)).join('');
      
      const base64Result = decodeBase64(encodeBase64(allBytes));
      expect(base64Result).toBe(allBytes);
      
      const hexResult = decodeHex(encodeHex(allBytes));
      expect(hexResult).toBe(allBytes);
    });
  });

  describe('Performance & Concurrency', () => {
    it('should handle concurrent operations', async () => {
      const testData = 'Hello World';
      const promises: Promise<string>[] = [];
      
      // Run 100 concurrent encoding operations
      for (let i = 0; i < 100; i++) {
        promises.push(Promise.resolve(encodeBase64(testData + i)));
      }
      
      const results = await Promise.all(promises);
      
      // Verify all results
      for (let i = 0; i < 100; i++) {
        const decoded = decodeBase64(results[i]);
        expect(decoded).toBe(testData + i);
      }
    });

    it('should be stateless across calls', () => {
      const data1 = 'First call';
      const data2 = 'Second call';
      
      const encoded1a = encodeBase64(data1);
      const encoded2 = encodeBase64(data2);
      const encoded1b = encodeBase64(data1);
      
      // Same input should always produce same output
      expect(encoded1a).toBe(encoded1b);
      expect(encoded1a).not.toBe(encoded2);
    });

    it('should handle rapid sequential operations', () => {
      const testData = 'Performance test';
      
      // Rapid fire operations
      for (let i = 0; i < 1000; i++) {
        const encoded = encodeBase64(testData);
        const decoded = decodeBase64(encoded);
        expect(decoded).toBe(testData);
      }
    });
  });
});
