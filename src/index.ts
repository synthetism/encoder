/**
 * @synet/encoder - Conscious Encoding/Decoding Unit
 * 
 * Zero-dependency encoding operations following Unit Architecture doctrine.
 * 
 * EXPORTS:
 * - Encoder: Complete conscious encoder unit with teach/learn capabilities
 * - Pure functions: Simple functional encoding operations  
 * - Result: Foundational error handling pattern
 * - Types: All encoding-related interfaces
 */

// Core Unit
export { Encoder } from './encoder.unit.js';

// Result pattern (foundational)
export { Result } from './result.js';

// Types
export type {
  EncoderConfig,
  EncoderProps,
  EncodingFormat,
  EncodingResult,
  DecodingResult,
  DetectionResult,
  ValidationResult
} from './encoder.unit.js';

// Pure function exports for simple use cases
export { 
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
  type EncodingFormat as FunctionEncodingFormat
} from './functions.js';
