/**
 * Encoder Unit Tests - Unit Architecture Compliance & Core Operations
 * 
 * Tests both the conscious Unit and all encoding operations
 * following Unit Architecture v1.0.6 patterns
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Encoder } from '../src/encoder.unit.js';

describe('Encoder Unit - Architecture Compliance', () => {
  let encoder: Encoder;

  beforeEach(() => {
    encoder = Encoder.create();
  });

  describe('Unit Architecture Doctrines', () => {


    it('should follow Doctrine #7: EVERY UNIT MUST HAVE DNA', () => {
      expect(encoder.dna).toBeDefined();
      expect(encoder.dna.id).toBe('encoder');
      expect(encoder.dna.version).toBe('1.0.0');
    });

    it('should follow Doctrine #2: TEACH/LEARN PARADIGM', () => {
      expect(typeof encoder.teach).toBe('function');
      expect(typeof encoder.learn).toBe('function');
    });

    it('should follow Doctrine #11: ALWAYS HELP', () => {
      expect(typeof encoder.help).toBe('function');
      expect(() => encoder.help()).not.toThrow();
    });

    it('should follow Doctrine #9: ALWAYS TEACH', () => {
      const contract = encoder.teach();
      expect(contract).toBeDefined();
      expect(contract.unitId).toBe('encoder');
      expect(contract.capabilities).toBeDefined();
      
      // Should teach native capabilities
      expect(contract.capabilities.encode).toBeDefined();
      expect(contract.capabilities.decode).toBeDefined();
      expect(contract.capabilities.detect).toBeDefined();
      expect(contract.capabilities.validate).toBeDefined();
    });

    it('should follow Doctrine #12: NAMESPACE EVERYTHING', () => {
      const contract = encoder.teach();
      expect(contract.unitId).toBe('encoder');
      
      // When learned by other units, capabilities will be namespaced as "encoder.encode", etc.
    });

    it('should follow Doctrine #22: STATELESS OPERATIONS', () => {
      // Capabilities are only for learned abilities, not native methods
      const learnedCapabilities = encoder.capabilities();
      expect(Array.isArray(learnedCapabilities)).toBe(true);
      // New encoder has no learned capabilities
      expect(learnedCapabilities).toHaveLength(0);
    });

    it('should provide proper whoami identification', () => {
      const identity = encoder.whoami();
      expect(identity).toContain('EncoderUnit');
      expect(identity).toContain('encoder');
      expect(identity).toContain('1.0.0');
    });
  });

  describe('Configuration & State Management', () => {
    it('should create with default configuration', () => {
      const defaultEncoder = Encoder.create();
      const state = defaultEncoder.toJSON();
      
      expect(state.defaultFormat).toBe('base64');
      expect(state.strictMode).toBe(false);
      expect(state.autoDetect).toBe(true);
    });

    it('should create with custom configuration', () => {
      const customEncoder = Encoder.create({
        defaultFormat: 'hex',
        strictMode: true,
        autoDetect: false,
        maxInputSize: 1024
      });
      
      const state = customEncoder.toJSON();
      expect(state.defaultFormat).toBe('hex');
      expect(state.strictMode).toBe(true);
      expect(state.autoDetect).toBe(false);
    });

    it('should track stateless operation design', () => {
      const encoder = Encoder.create();
      
      // Perform operations - should not change unit state
      encoder.encode('test1', 'base64');
      encoder.encode('test2', 'hex');
      
      // Unit should remain stateless - capabilities are only for learned abilities
      const learnedCapabilities = encoder.capabilities();
      expect(learnedCapabilities).toHaveLength(0); // No learned capabilities initially
    });
  });
});

describe('Encoder Unit - Core Encoding Operations', () => {
  let encoder: Encoder;

  beforeEach(() => {
    encoder = Encoder.create();
  });

  describe('Base64 Encoding', () => {
    it('should encode text to base64', () => {
      const result = encoder.encode('Hello World', 'base64');
      expect(result.isSuccess).toBe(true);
      expect(result.value.encoded).toBe('SGVsbG8gV29ybGQ=');
      expect(result.value.format).toBe('base64');
      expect(result.value.originalSize).toBe(11);
    });

    it('should decode base64 text', () => {
      const result = encoder.decode('SGVsbG8gV29ybGQ=', 'base64');
      expect(result.isSuccess).toBe(true);
      expect(result.value.decoded).toBe('Hello World');
      expect(result.value.detectedFormat).toBe('base64');
    });

    it('should handle unicode characters', () => {
      const unicode = '🚀 Hello 世界';
      const encoded = encoder.encode(unicode, 'base64');
      expect(encoded.isSuccess).toBe(true);
      
      const decoded = encoder.decode(encoded.value.encoded, 'base64');
      expect(decoded.isSuccess).toBe(true);
      expect(decoded.value.decoded).toBe(unicode);
    });

    it('should validate base64 format', () => {
      const validation = encoder.validate('SGVsbG8gV29ybGQ=', 'base64');
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
      
      const invalidValidation = encoder.validate('SGVsbG8gV29ybGQ', 'base64');
      expect(invalidValidation.isValid).toBe(false);
      expect(invalidValidation.errors.length).toBeGreaterThan(0);
    });
  });

  describe('Base64URL Encoding', () => {
    it('should encode text to base64url', () => {
      const result = encoder.encode('Hello World!', 'base64url');
      expect(result.isSuccess).toBe(true);
      expect(result.value.encoded).toBe('SGVsbG8gV29ybGQh');
      expect(result.value.format).toBe('base64url');
    });

    it('should decode base64url text', () => {
      const result = encoder.decode('SGVsbG8gV29ybGQh', 'base64url');
      expect(result.isSuccess).toBe(true);
      expect(result.value.decoded).toBe('Hello World!');
    });

    it('should handle URL-unsafe characters correctly', () => {
      const text = 'Hello+World/Test=';
      const encoded = encoder.encode(text, 'base64url');
      expect(encoded.isSuccess).toBe(true);
      expect(encoded.value.encoded).not.toContain('+');
      expect(encoded.value.encoded).not.toContain('/');
      expect(encoded.value.encoded).not.toContain('=');
      
      const decoded = encoder.decode(encoded.value.encoded, 'base64url');
      expect(decoded.value.decoded).toBe(text);
    });
  });

  describe('Hexadecimal Encoding', () => {
    it('should encode text to hex', () => {
      const result = encoder.encode('Hello', 'hex');
      expect(result.isSuccess).toBe(true);
      expect(result.value.encoded).toBe('48656c6c6f');
    });

    it('should decode hex text', () => {
      const result = encoder.decode('48656c6c6f', 'hex');
      expect(result.isSuccess).toBe(true);
      expect(result.value.decoded).toBe('Hello');
    });

    it('should handle both uppercase and lowercase hex', () => {
      const lowerResult = encoder.decode('48656c6c6f', 'hex');
      const upperResult = encoder.decode('48656C6C6F', 'hex');
      
      expect(lowerResult.value.decoded).toBe('Hello');
      expect(upperResult.value.decoded).toBe('Hello');
    });

    it('should validate hex format', () => {
      const validation = encoder.validate('48656c6c6f', 'hex');
      expect(validation.isValid).toBe(true);
      
      const invalidValidation = encoder.validate('48656c6c6g', 'hex');
      expect(invalidValidation.isValid).toBe(false);
      expect(invalidValidation.errors).toContain('Contains invalid hexadecimal characters');
    });
  });

  describe('URI Encoding', () => {
    it('should encode text for URI', () => {
      const result = encoder.encode('Hello World!', 'uri');
      expect(result.isSuccess).toBe(true);
      expect(result.value.encoded).toBe('Hello%20World!');
    });

    it('should decode URI encoded text', () => {
      const result = encoder.decode('Hello%20World!', 'uri');
      expect(result.isSuccess).toBe(true);
      expect(result.value.decoded).toBe('Hello World!');
    });

    it('should handle special characters', () => {
      const special = 'test@example.com?param=value&other=test';
      const encoded = encoder.encode(special, 'uri');
      expect(encoded.isSuccess).toBe(true);
      
      const decoded = encoder.decode(encoded.value.encoded, 'uri');
      expect(decoded.value.decoded).toBe(special);
    });
  });

  describe('ASCII Encoding', () => {
    it('should encode ASCII text', () => {
      const result = encoder.encode('Hello World', 'ascii');
      expect(result.isSuccess).toBe(true);
      expect(result.value.encoded).toBe('Hello World');
    });

    it('should reject non-ASCII characters in strict mode', () => {
      const strictEncoder = Encoder.create({ strictMode: true });
      const result = strictEncoder.encode('Hello 世界', 'ascii');
      expect(result.isFailure).toBe(true);
      expect(result.error).toContain('Non-ASCII character found');
    });

    it('should validate ASCII format', () => {
      const validation = encoder.validate('Hello World', 'ascii');
      expect(validation.isValid).toBe(true);
      
      const invalidValidation = encoder.validate('Hello 世界', 'ascii');
      expect(invalidValidation.isValid).toBe(false);
    });
  });
});

describe('Encoder Unit - Advanced Operations', () => {
  let encoder: Encoder;

  beforeEach(() => {
    encoder = Encoder.create();
  });

  describe('Format Detection', () => {
    it('should detect base64 format', () => {
      const detection = encoder.detect('SGVsbG8gV29ybGQ=');
      expect(detection.format).toBe('base64');
      expect(detection.confidence).toBeGreaterThan(0.8);
    });

    it('should detect hex format', () => {
      const detection = encoder.detect('48656c6c6f');
      expect(detection.format).toBe('hex');
      expect(detection.confidence).toBeGreaterThan(0.9);
    });

    it('should detect base64url format', () => {
      const detection = encoder.detect('SGVsbG8gV29ybGQh');
      expect(detection.format).toBe('base64url');
      expect(detection.confidence).toBeGreaterThan(0.8);
    });

    it('should detect URI encoding', () => {
      const detection = encoder.detect('Hello%20World!');
      expect(detection.format).toBe('uri');
      expect(detection.confidence).toBeGreaterThan(0.7);
    });

    it('should detect ASCII format', () => {
      const detection = encoder.detect('Hello World');
      expect(detection.format).toBe('ascii');
      expect(detection.confidence).toBeGreaterThan(0.6);
    });

    it('should throw for undetectable formats', () => {
      expect(() => encoder.detect('🚀💫🌟')).toThrow();
    });
  });

  describe('Chain Operations', () => {
    it('should chain multiple encodings', () => {
      const result = encoder.chain('Hello', ['hex', 'base64']);
      expect(result.isSuccess).toBe(true);
      
      // First hex: 'Hello' -> '48656c6c6f'
      // Then base64: '48656c6c6f' -> 'NDg2NTZjNmM2Zg=='
      expect(result.value.encoded).toBe('NDg2NTZjNmM2Zg==');
      expect(result.value.format).toBe('base64');
    });

    it('should reverse chain decodings', () => {
      const original = 'Hello World';
      const chained = encoder.chain(original, ['hex', 'base64', 'uri']);
      expect(chained.isSuccess).toBe(true);
      
      const reversed = encoder.reverse(chained.value.encoded, ['hex', 'base64', 'uri']);
      expect(reversed.isSuccess).toBe(true);
      expect(reversed.value.decoded).toBe(original);
    });

    it('should handle chain failures gracefully', () => {
      // Create an encoder that will fail during encoding
      const encoder_strict = Encoder.create({ strictMode: true, maxInputSize: 5 });
      
      // This should fail because input exceeds maxInputSize
      const result = encoder_strict.chain('Hello World - this is too long', ['base64', 'hex']);
      
      
      expect(result.isFailure).toBe(true);
      expect(result.error).toContain('Chain failed');
    });

    it('should calculate compression ratios', () => {
      const result = encoder.chain('Hello', ['hex']);
      expect(result.isSuccess).toBe(true);
      expect(result.value.compressionRatio).toBeCloseTo(2.0); // hex doubles size
      
      const base64Result = encoder.encode('Hello', 'base64');
      expect(base64Result.value.compressionRatio).toBeCloseTo(1.6); // base64 ~60% increase
    });
  });

  describe('Auto-detection Decoding', () => {
    it('should auto-detect and decode base64', () => {
      const result = encoder.decode('SGVsbG8gV29ybGQ='); // no format specified
      expect(result.isSuccess).toBe(true);
      expect(result.value.decoded).toBe('Hello World');
      expect(result.value.detectedFormat).toBe('base64');
    });

    it('should auto-detect and decode hex', () => {
      const result = encoder.decode('48656c6c6f'); // no format specified
      expect(result.isSuccess).toBe(true);
      expect(result.value.decoded).toBe('Hello');
      expect(result.value.detectedFormat).toBe('hex');
    });

    it('should disable auto-detection when configured', () => {
      const noAutoDetect = Encoder.create({ autoDetect: false, defaultFormat: 'hex' });
      const result = noAutoDetect.decode('SGVsbG8gV29ybGQ='); // base64 data

      
      expect(result.isFailure).toBe(true); // should fail as it tries to decode as hex
      expect(result.error).toContain('Invalid hex format');
    });
  });

  describe('Error Handling & Validation', () => {
    it('should handle large input validation', () => {
      const smallLimitEncoder = Encoder.create({ maxInputSize: 10 });
      const result = smallLimitEncoder.encode('This is a very long string that exceeds the limit');
      expect(result.isFailure).toBe(true);
      expect(result.error).toContain('Input too large');
    });

    it('should provide detailed validation errors', () => {
      const validation = encoder.validate('SGVsbG8', 'base64'); // missing padding
      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Invalid base64 length (must be multiple of 4)');
      expect(validation.suggestions).toContain('Add padding with = characters');
    });

    it('should handle output validation', () => {
      // This test verifies that output validation works
      const encoder_with_validation = Encoder.create({ validateOutput: true });
      const result = encoder_with_validation.encode('Hello', 'base64');
      expect(result.isSuccess).toBe(true); // Should pass validation
    });

    it('should provide error causes in Result failures', () => {
      const result = encoder.decode('invalid-base64-data!@#$', 'base64');
      
      expect(result.isFailure).toBe(true);
      expect(result.errorCause).toBeDefined();
    });
  });

  describe('Teaching & Learning Integration', () => {
    it('should teach capabilities with proper signatures', () => {
      const contract = encoder.teach();
      
      // Test that taught capabilities work
      const encodeCapability = contract.capabilities.encode as Function;
      expect(typeof encodeCapability).toBe('function');
      
      // Should work when called through teaching contract
      const result = encodeCapability('Hello', 'base64');
      expect(result.isSuccess).toBe(true);
    });

    it('should maintain consistent metadata access', () => {
      const contract = encoder.teach();
      
      const getDefaultFormat = contract.capabilities.getDefaultFormat as Function;
      const isStrictMode = contract.capabilities.isStrictMode as Function;
      
      expect(getDefaultFormat()).toBe('base64');
      expect(typeof isStrictMode()).toBe('boolean');
    });
  });
});
