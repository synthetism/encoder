/**
 * Encoder Unit - Conscious Encoding/Decoding Operations
 * 
 * SYNET Unit Architecture v1.0.6 Implementation
 * 
 * Philosophy: One unit, one goal - reliable data transformation
 * 
 * Native Capabilities:
 * - encode() - Transform data to specified format
 * - decode() - Reverse transformation with validation  
 * - detect() - Auto-detect encoding format
 * - validate() - Verify encoded data integrity
 * - chain() - Sequential encoding operations
 * 
 * Supported Formats: Base64, Base64URL, Hex, URI, ASCII
 * 
 * @author SYNET ALPHA
 * @version 1.0.0
 * @follows Unit Architecture Doctrine v1.0.6
 */

import { Unit, createUnitSchema, type UnitProps, type TeachingContract } from '@synet/unit';
import { Result } from './result.js';

// Doctrine #13: TYPE HIERARCHY CONSISTENCY (Config → Props → State → Output)

/**
 * External input configuration for static create()
 */
export interface EncoderConfig {
  defaultFormat?: EncodingFormat;
  strictMode?: boolean;
  autoDetect?: boolean;
  maxInputSize?: number;
  validateOutput?: boolean;
}

/**
 * Internal state after validation (implements UnitProps)
 */
export interface EncoderProps extends UnitProps {
  defaultFormat: EncodingFormat;
  strictMode: boolean;
  autoDetect: boolean;
  maxInputSize: number;
  validateOutput: boolean;
  readonly created: Date;
}

/**
 * Encoding format types
 */
export type EncodingFormat = 'base64' | 'base64url' | 'hex' | 'uri' | 'ascii';

/**
 * Encoding operation result
 */
export interface EncodingResult {
  readonly encoded: string;
  readonly originalSize: number;
  readonly encodedSize: number;
  readonly format: EncodingFormat;
  readonly compressionRatio: number;
  readonly timestamp: Date;
}

/**
 * Decoding operation result
 */
export interface DecodingResult {
  readonly decoded: string;
  readonly detectedFormat: EncodingFormat;
  readonly isValid: boolean;
  readonly originalSize: number;
  readonly timestamp: Date;
}

/**
 * Format detection result
 */
export interface DetectionResult {
  readonly format: EncodingFormat;
  readonly confidence: number;
  readonly reasons: string[];
  readonly timestamp: Date;
}

/**
 * Validation result
 */
export interface ValidationResult {
  readonly isValid: boolean;
  readonly format: EncodingFormat;
  readonly errors: string[];
  readonly suggestions: string[];
}

/**
 * Encoder Implementation
 * 
 * Doctrine #1: ZERO DEPENDENCY (only Node.js/browser native APIs)
 * Doctrine #17: VALUE OBJECT FOUNDATION (immutable with identity and capabilities)
 */
export class Encoder extends Unit<EncoderProps> {
  
  // Doctrine #4: CREATE NOT CONSTRUCT (protected constructor)
  protected constructor(props: EncoderProps) {
    super(props);
  }

  // Doctrine #4: CREATE NOT CONSTRUCT (static create with validation)
  static create(config: EncoderConfig = {}): Encoder {
    // Doctrine #3: PROPS CONTAIN EVERYTHING (validate and transform config to props)
    const props: EncoderProps = {
      // Doctrine #7: EVERY UNIT MUST HAVE DNA
      dna: createUnitSchema({ 
        id: 'encoder', 
        version: '1.0.0' 
      }),
      defaultFormat: config.defaultFormat || 'base64',
      strictMode: config.strictMode ?? false,
      autoDetect: config.autoDetect ?? true,
      maxInputSize: config.maxInputSize || 10 * 1024 * 1024, // 10MB default
      validateOutput: config.validateOutput ?? true,
      created: new Date()
    };
    
    return new Encoder(props);
  }

  // Doctrine #11: ALWAYS HELP (living documentation)
  help(): void {
    console.log(`


Hi, I am Encoder Unit [${this.dna.id}] v${this.dna.version} - Data Transformation Service

IDENTITY: ${this.whoami()}
DEFAULT FORMAT: ${this.props.defaultFormat}
STRICT MODE: ${this.props.strictMode}
AUTO DETECT: ${this.props.autoDetect}
MAX INPUT: ${(this.props.maxInputSize / 1024 / 1024).toFixed(1)}MB
STATUS: IMMUTABLE (stateless operations)

NATIVE CAPABILITIES:
• encode(data, format?) - Transform data to specified format (Result for validation)
• decode(data, format?) - Reverse transformation with auto-detection (Result)
• detect(data) - Auto-detect encoding format with confidence (throws on error)
• validate(data, format) - Verify encoded data integrity (throws on error)
• chain(data, formats) - Sequential encoding operations (Result)
• reverse(data, formats) - Reverse sequential decoding (Result)

SUPPORTED FORMATS:
• base64: Standard Base64 encoding (RFC 4648)
• base64url: URL-safe Base64 encoding
• hex: Hexadecimal encoding (lowercase)
• uri: URI component encoding
• ascii: ASCII text encoding

USAGE EXAMPLES:
  const encoder = Encoder.create();
  
  // Simple operations (Result pattern for validation)
  const encoded = encoder.encode('Hello World', 'base64');
  if (encoded.isSuccess) {
    console.log(encoded.value.encoded); // SGVsbG8gV29ybGQ=
  }
  
  // Auto-detection decoding
  const decoded = encoder.decode('SGVsbG8gV29ybGQ=');
  if (decoded.isSuccess) {
    console.log(decoded.value.decoded); // Hello World
  }
  
  // Format detection
  const format = encoder.detect('48656c6c6f'); // hex
  console.log(format.format); // 'hex'

LEARNING CAPABILITIES:
Other units can learn from me:
  unit.learn([encoder.teach()]);
  unit.execute('encoder.encode', data, format);

I TEACH:
• encode(data, format) - Encoding capability
• decode(data, format) - Decoding capability  
• detect(data) - Format detection capability
• validate(data, format) - Validation capability
• chain(data, formats) - Sequential encoding capability

`);
  }

  // Doctrine #2: TEACH/LEARN PARADIGM (every unit must teach)
  // Doctrine #9: ALWAYS TEACH (explicit capability binding)
  // Doctrine #19: CAPABILITY LEAKAGE PREVENTION (teach only native capabilities)
  teach(): TeachingContract {
    return {
      // Doctrine #12: NAMESPACE EVERYTHING (unitId for namespacing)
      unitId: this.dna.id,
      capabilities: {
        // Native encoding capabilities only - wrapped for unknown[] compatibility
        encode: ((...args: unknown[]) => this.encode(args[0] as string, args[1] as EncodingFormat)) as (...args: unknown[]) => unknown,
        decode: ((...args: unknown[]) => this.decode(args[0] as string, args[1] as EncodingFormat)) as (...args: unknown[]) => unknown,
        detect: ((...args: unknown[]) => this.detect(args[0] as string)) as (...args: unknown[]) => unknown,
        validate: ((...args: unknown[]) => this.validate(args[0] as string, args[1] as EncodingFormat)) as (...args: unknown[]) => unknown,
        chain: ((...args: unknown[]) => this.chain(args[0] as string, args[1] as EncodingFormat[])) as (...args: unknown[]) => unknown,
        
        // Metadata access
        getDefaultFormat: (() => this.props.defaultFormat) as (...args: unknown[]) => unknown,
        isStrictMode: (() => this.props.strictMode) as (...args: unknown[]) => unknown,
        getMaxInputSize: (() => this.props.maxInputSize) as (...args: unknown[]) => unknown
      }
    };
  }

  // Doctrine #14: ERROR BOUNDARY CLARITY (Result for complex operations)

  /**
   * Encode data to specified format (Result - complex validation operation)
   */
  encode(data: string, format?: EncodingFormat): Result<EncodingResult> {
    try {
      const encodingFormat = format || this.props.defaultFormat;
      
      // Input validation
      if (data.length > this.props.maxInputSize) {
        return Result.fail(`Input too large: ${data.length} bytes (max: ${this.props.maxInputSize})`);
      }

      if (this.props.strictMode && !this.isValidInput(data)) {
        return Result.fail('Invalid input for strict mode');
      }

      const encoded = this.performEncode(data, encodingFormat);
      
      // Output validation if enabled
      if (this.props.validateOutput) {
        const validation = this.validate(encoded, encodingFormat);
        if (!validation.isValid) {
          return Result.fail(`Output validation failed: ${validation.errors.join(', ')}`);
        }
      }

      const result: EncodingResult = {
        encoded,
        originalSize: data.length,
        encodedSize: encoded.length,
        format: encodingFormat,
        compressionRatio: encoded.length / data.length,
        timestamp: new Date()
      };

      return Result.success(result);
    } catch (error) {
      return Result.fail(
        `Encoding failed: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    }
  }

  /**
   * Decode data with optional format hint (Result - complex auto-detection operation)
   */
  decode(data: string, format?: EncodingFormat): Result<DecodingResult> {
    try {
      // Auto-detect format if not provided and auto-detection is enabled
      let detectedFormat: EncodingFormat;
      if (format) {
        detectedFormat = format;
      } else if (this.props.autoDetect) {
        detectedFormat = this.detect(data).format;
      } else {
        detectedFormat = this.props.defaultFormat;
      }
      
      // Input validation
      const validation = this.validate(data, detectedFormat);
      if (!validation.isValid) {
        if (this.props.strictMode) {
          return Result.fail(`Invalid ${detectedFormat} format: ${validation.errors.join(', ')}`);
        }
        // In non-strict mode, still fail if the format is completely wrong
        if (validation.errors.some(err => err.includes('invalid') || err.includes('Invalid'))) {
          return Result.fail(
            `Invalid ${detectedFormat} format: ${validation.errors.join(', ')}`,
            new Error(`Validation failed for ${detectedFormat}`)
          );
        }
      }

      const decoded = this.performDecode(data, detectedFormat);

      const result: DecodingResult = {
        decoded,
        detectedFormat,
        isValid: validation.isValid,
        originalSize: data.length,
        timestamp: new Date()
      };

      return Result.success(result);
    } catch (error) {
      return Result.fail(
        `Decoding failed: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    }
  }

  /**
   * Chain multiple encoding operations (Result - complex multi-step operation)
   */
  chain(data: string, formats: EncodingFormat[]): Result<EncodingResult> {
    try {
      let result = data;
      let totalRatio = 1;
      
      for (const format of formats) {
        const encoded = this.encode(result, format);
        if (encoded.isFailure) {
          return Result.fail(`Chain failed at ${format}: ${encoded.error}`);
        }
        result = encoded.value.encoded;
        totalRatio *= encoded.value.compressionRatio;
      }

      const chainResult: EncodingResult = {
        encoded: result,
        originalSize: data.length,
        encodedSize: result.length,
        format: formats[formats.length - 1], // Final format
        compressionRatio: totalRatio,
        timestamp: new Date()
      };

      return Result.success(chainResult);
    } catch (error) {
      return Result.fail(
        `Chain encoding failed: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    }
  }

  /**
   * Reverse chain decoding (Result - complex multi-step operation)
   */
  reverse(data: string, formats: EncodingFormat[]): Result<DecodingResult> {
    try {
      let result = data;
      const reversedFormats = [...formats].reverse();
      
      for (const format of reversedFormats) {
        const decoded = this.decode(result, format);
        if (decoded.isFailure) {
          return Result.fail(`Reverse chain failed at ${format}: ${decoded.error}`);
        }
        result = decoded.value.decoded;
      }

      const reverseResult: DecodingResult = {
        decoded: result,
        detectedFormat: formats[0], // Original format
        isValid: true,
        originalSize: data.length,
        timestamp: new Date()
      };

      return Result.success(reverseResult);
    } catch (error) {
      return Result.fail(
        `Reverse chain failed: ${error instanceof Error ? error.message : String(error)}`,
        error
      );
    }
  }

  // Doctrine #14: ERROR BOUNDARY CLARITY (throws for simple operations)

  /**
   * Auto-detect encoding format (throw on error - simple classification operation)
   */
  detect(data: string): DetectionResult {
    const patterns: Array<{ format: EncodingFormat; test: (s: string) => boolean; confidence: number; reason: string }> = [
      {
        format: 'hex',
        test: (s) => /^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0,
        confidence: 0.95,
        reason: 'Matches hexadecimal pattern with even length'
      },
      {
        format: 'base64url',
        test: (s) => /^[A-Za-z0-9\-_]*$/.test(s) && !s.includes('+') && !s.includes('/') && !s.includes('=') && s.length > 0,
        confidence: 0.9,
        reason: 'Matches base64url character set (URL-safe, no padding)'
      },
      {
        format: 'base64',
        test: (s) => /^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length % 4 === 0 && (s.includes('+') || s.includes('/') || s.includes('=')),
        confidence: 0.85,
        reason: 'Matches base64 character set with standard chars or padding'
      },
      {
        format: 'uri',
        test: (s) => s.includes('%') && /^[A-Za-z0-9\-_.~%!*'()]+$/.test(s),
        confidence: 0.8,
        reason: 'Contains URI percent-encoding characters'
      },
      {
        format: 'ascii',
        test: (s) => /^[\x20-\x7E]*$/.test(s),
        confidence: 0.7,
        reason: 'Contains only printable ASCII characters'
      }
    ];

    const matches = patterns.filter(p => p.test(data));
    
    if (matches.length === 0) {
      throw new Error(`Cannot detect encoding format for data: ${data.slice(0, 50)}...`);
    }

    // Return highest confidence match
    const bestMatch = matches.reduce((best, current) => 
      current.confidence > best.confidence ? current : best
    );

    return {
      format: bestMatch.format,
      confidence: bestMatch.confidence,
      reasons: matches.map(m => m.reason),
      timestamp: new Date()
    };
  }

  /**
   * Validate encoded data format (throw on error - simple validation operation)
   */
  validate(data: string, format: EncodingFormat): ValidationResult {
    const errors: string[] = [];
    const suggestions: string[] = [];

    try {
      switch (format) {
        case 'base64':
          if (!/^[A-Za-z0-9+/]*={0,2}$/.test(data)) {
            errors.push('Contains invalid base64 characters');
            suggestions.push('Remove invalid characters or try base64url format');
          }
          if (data.length % 4 !== 0) {
            errors.push('Invalid base64 length (must be multiple of 4)');
            suggestions.push('Add padding with = characters');
          }
          break;

        case 'base64url':
          if (!/^[A-Za-z0-9\-_]*$/.test(data)) {
            errors.push('Contains invalid base64url characters');
            suggestions.push('Use only A-Z, a-z, 0-9, -, _ characters');
          }
          break;

        case 'hex':
          if (!/^[0-9a-fA-F]*$/.test(data)) {
            errors.push('Contains invalid hexadecimal characters');
            suggestions.push('Use only 0-9, a-f, A-F characters');
          }
          if (data.length % 2 !== 0) {
            errors.push('Invalid hex length (must be even)');
            suggestions.push('Add leading zero or remove extra character');
          }
          break;

        case 'uri':
          try {
            decodeURIComponent(data);
          } catch {
            errors.push('Invalid URI encoding');
            suggestions.push('Check percent-encoding format');
          }
          break;

        case 'ascii':
          if (!/^[\x20-\x7E]*$/.test(data)) {
            errors.push('Contains non-ASCII characters');
            suggestions.push('Use only printable ASCII characters (32-126)');
          }
          break;

        default:
          throw new Error(`Unknown format: ${format}`);
      }

      return {
        isValid: errors.length === 0,
        format,
        errors,
        suggestions
      };
    } catch (error) {
      throw new Error(`Validation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Doctrine #8: PURE FUNCTION HEARTS (core logic as pure functions)

  private performEncode(data: string, format: EncodingFormat): string {
    switch (format) {
      case 'base64':
        return this.encodeBase64(data);
      case 'base64url':
        return this.encodeBase64URL(data);
      case 'hex':
        return this.encodeHex(data);
      case 'uri':
        return this.encodeURI(data);
      case 'ascii':
        return this.encodeASCII(data);
      default:
        throw new Error(`Unsupported encoding format: ${format}`);
    }
  }

  private performDecode(data: string, format: EncodingFormat): string {
    switch (format) {
      case 'base64':
        return this.decodeBase64(data);
      case 'base64url':
        return this.decodeBase64URL(data);
      case 'hex':
        return this.decodeHex(data);
      case 'uri':
        return this.decodeURI(data);
      case 'ascii':
        return this.decodeASCII(data);
      default:
        throw new Error(`Unsupported decoding format: ${format}`);
    }
  }

  // Base64 implementation (cross-platform Node.js/Browser)
  private encodeBase64(data: string): string {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(data, 'utf8').toString('base64');
    }
    if (typeof btoa !== 'undefined') {
      // Modern Unicode-safe base64 encoding without deprecated unescape()
      const bytes = new TextEncoder().encode(data);
      const binaryString = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
      return btoa(binaryString);
    }
    throw new Error('No base64 encoding available');
  }

  private decodeBase64(data: string): string {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(data, 'base64').toString('utf8');
    }
    if (typeof atob !== 'undefined') {
      // Modern Unicode-safe base64 decoding without deprecated escape()
      const binaryString = atob(data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return new TextDecoder('utf-8').decode(bytes);
    }
    throw new Error('No base64 decoding available');
  }

  // Base64URL implementation
  private encodeBase64URL(data: string): string {
    return this.encodeBase64(data)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  private decodeBase64URL(data: string): string {
    let base64 = data.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return this.decodeBase64(base64);
  }

  // Hex implementation
  private encodeHex(data: string): string {
    return Array.from(data)
      .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
  }

  private decodeHex(data: string): string {
    const hex = data.replace(/[^0-9a-fA-F]/g, '');
    let result = '';
    for (let i = 0; i < hex.length; i += 2) {
      result += String.fromCharCode(Number.parseInt(hex.slice(i, i + 2), 16));
    }
    return result;
  }

  // URI implementation
  private encodeURI(data: string): string {
    return encodeURIComponent(data);
  }

  private decodeURI(data: string): string {
    return decodeURIComponent(data);
  }

  // ASCII implementation
  private encodeASCII(data: string): string {
    return Array.from(data)
      .map(char => {
        const code = char.charCodeAt(0);
        if (code > 127) {
          throw new Error(`Non-ASCII character found: ${char} (code: ${code})`);
        }
        return char;
      })
      .join('');
  }

  private decodeASCII(data: string): string {
    return data; // ASCII is already decoded
  }

  // Utility methods
  private isValidInput(data: string): boolean {
    // Basic input validation for strict mode
    return typeof data === 'string' && data.length > 0;
  }

  // Standard unit identification
  whoami(): string {
    return `EncoderUnit[${this.dna.id}@${this.dna.version}]`;
  }

  // JSON serialization (no sensitive data exposed)
  toJSON(): Record<string, unknown> {
    return {
      type: 'EncoderUnit',
      dna: this.dna,
      defaultFormat: this.props.defaultFormat,
      strictMode: this.props.strictMode,
      autoDetect: this.props.autoDetect,
      learnedCapabilities: this.capabilities(), // This calls the base Unit class method
      created: this.props.created
    };
  }
}
