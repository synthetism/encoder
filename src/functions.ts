/**
 * Pure Encoding Functions - Serverless Ready
 * 
 * Simple, stateless functions for encoding/decoding operations.
 * These throw on error (simple operations) following Doctrine #14.
 */

/**
 * Encoding format types
 */
export type EncodingFormat = 'base64' | 'base64url' | 'hex' | 'uri' | 'ascii';

/**
 * Encode string to Base64
 */
export function encodeBase64(data: string): string {
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

/**
 * Decode Base64 string
 */
export function decodeBase64(data: string): string {
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

/**
 * Encode string to Base64URL (URL-safe)
 */
export function encodeBase64URL(data: string): string {
  return encodeBase64(data)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decode Base64URL string
 */
export function decodeBase64URL(data: string): string {
  let base64 = data.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return decodeBase64(base64);
}

/**
 * Encode string to hexadecimal
 */
export function encodeHex(data: string): string {
  return Array.from(data)
    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decode hexadecimal string
 */
export function decodeHex(data: string): string {
  if (data.length % 2 !== 0) {
    throw new Error('Invalid hex string: length must be even');
  }
  
  if (!/^[0-9a-fA-F]*$/.test(data)) {
    throw new Error('Invalid hex string: contains non-hex characters');
  }
  
  let result = '';
  for (let i = 0; i < data.length; i += 2) {
    result += String.fromCharCode(Number.parseInt(data.slice(i, i + 2), 16));
  }
  return result;
}

/**
 * Encode string for URI
 */
export function encodeURIString(data: string): string {
  return encodeURIComponent(data);
}

/**
 * Decode URI-encoded string
 */
export function decodeURIString(data: string): string {
  return decodeURIComponent(data);
}

/**
 * Encode string as ASCII (validates ASCII-only)
 */
export function encodeASCII(data: string): string {
  for (let i = 0; i < data.length; i++) {
    const code = data.charCodeAt(i);
    if (code > 127) {
      throw new Error(`Non-ASCII character found at position ${i}: '${data[i]}' (code: ${code})`);
    }
  }
  return data;
}

/**
 * Decode ASCII string (no-op, validates printable ASCII)
 */
export function decodeASCII(data: string): string {
  for (let i = 0; i < data.length; i++) {
    const code = data.charCodeAt(i);
    if (code < 32 || code > 126) {
      throw new Error(`Non-printable ASCII character at position ${i}: code ${code}`);
    }
  }
  return data;
}

/**
 * Generic encode function
 */
export function encode(data: string, format: EncodingFormat): string {
  switch (format) {
    case 'base64':
      return encodeBase64(data);
    case 'base64url':
      return encodeBase64URL(data);
    case 'hex':
      return encodeHex(data);
    case 'uri':
      return encodeURIString(data);
    case 'ascii':
      return encodeASCII(data);
    default:
      throw new Error(`Unsupported encoding format: ${format}`);
  }
}

/**
 * Generic decode function
 */
export function decode(data: string, format: EncodingFormat): string {
  switch (format) {
    case 'base64':
      return decodeBase64(data);
    case 'base64url':
      return decodeBase64URL(data);
    case 'hex':
      return decodeHex(data);
    case 'uri':
      return decodeURIString(data);
    case 'ascii':
      return decodeASCII(data);
    default:
      throw new Error(`Unsupported decoding format: ${format}`);
  }
}

/**
 * Auto-detect encoding format
 */
export function detectFormat(data: string): EncodingFormat {
  // Test patterns in order of specificity/confidence
  if (/^[0-9a-fA-F]+$/.test(data) && data.length % 2 === 0) {
    return 'hex';
  }
  
  // Base64url should be tested before base64 since it's more restrictive
  if (/^[A-Za-z0-9\-_]*$/.test(data) && !data.includes('+') && !data.includes('/') && !data.includes('=') && data.length > 0) {
    return 'base64url';
  }
  
  // Base64 with standard characters or padding
  if (/^[A-Za-z0-9+/]*={0,2}$/.test(data) && data.length % 4 === 0 && (data.includes('+') || data.includes('/') || data.includes('='))) {
    return 'base64';
  }
  
  if (data.includes('%') && /^[A-Za-z0-9\-_.~%!*'()]+$/.test(data)) {
    return 'uri';
  }
  
  if (/^[\x20-\x7E]*$/.test(data)) {
    return 'ascii';
  }
  
  throw new Error(`Cannot detect encoding format for: ${data.slice(0, 50)}...`);
}

/**
 * Validate format of encoded data
 */
export function validateFormat(data: string, format: EncodingFormat): boolean {
  try {
    switch (format) {
      case 'base64':
        return /^[A-Za-z0-9+/]*={0,2}$/.test(data) && data.length % 4 === 0;
      case 'base64url':
        return /^[A-Za-z0-9\-_]*$/.test(data);
      case 'hex':
        return /^[0-9a-fA-F]*$/.test(data) && data.length % 2 === 0;
      case 'uri':
        decodeURIComponent(data);
        return true;
      case 'ascii':
        return /^[\x20-\x7E]*$/.test(data);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

/**
 * Chain multiple encodings
 */
export function chain(data: string, formats: EncodingFormat[]): string {
  let result = data;
  for (const format of formats) {
    result = encode(result, format);
  }
  return result;
}

/**
 * Reverse chain decodings
 */
export function reverseChain(data: string, formats: EncodingFormat[]): string {
  let result = data;
  for (const format of [...formats].reverse()) {
    result = decode(result, format);
  }
  return result;
}
