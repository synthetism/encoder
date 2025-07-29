# @synet/encoder

```bash
8""""                                       8   8               
8     eeeee eeee eeeee eeeee eeee eeeee     8   8 eeeee e eeeee 
8eeee 8   8 8  8 8  88 8   8 8    8   8     8e  8 8   8 8   8   
88    8e  8 8e   8   8 8e  8 8eee 8eee8e    88  8 8e  8 8e  8e  
88    88  8 88   8   8 88  8 88   88   8    88  8 88  8 88  88  
88eee 88  8 88e8 8eee8 88ee8 88ee 88   8    88ee8 88  8 88  88  
                                                                
version:1.0.0                                                                
```
**Production-ready Unit Architecture compliant encoding/decoding operations**

A conscious software unit that transforms data between multiple encoding formats with immutable design and comprehensive validation.

## Features

- **Unit Architecture Compliant** - Consciousness-based design with teaching/learning capabilities
- **Immutable by Design** - No mutable state, purely functional operations
- **Multiple Formats** - Base64, Base64URL, Hex, URI, ASCII encoding support
- **Auto-detection** - Intelligent format detection with confidence scoring
- **Pure Functions** - Serverless-ready stateless operations
- **Chainable Operations** - Sequential encoding/decoding workflows
- **Zero Dependencies** - Only Node.js/browser native APIs
- **Result Pattern** - Error-safe operations with validation
- **Teaching Capability** - Other units can learn encoding capabilities

## Installation

```bash
npm install @synet/encoder
```

## Quick Start

### Unit Architecture Pattern

```typescript
import { Encoder } from '@synet/encoder';

// Create encoder unit
const encoder = Encoder.create({
  defaultFormat: 'base64',
  autoDetect: true,
  strictMode: false
});

// Encode data (Result pattern for safety)
const encoded = encoder.encode('Hello World', 'base64');
if (encoded.isSuccess) {
  console.log(encoded.value.encoded); // SGVsbG8gV29ybGQ=
}

// Auto-detection decoding
const decoded = encoder.decode('48656c6c6f'); // Auto-detects hex
if (decoded.isSuccess) {
  console.log(decoded.value.decoded); // Hello
  console.log(decoded.value.detectedFormat); // hex
}

// Format detection
const detection = encoder.detect('SGVsbG8gV29ybGQh');
console.log(detection.format); // base64url
console.log(detection.confidence); // 0.9
```

### Pure Functions Pattern

```typescript
import { 
  encode, 
  decode, 
  base64Encode, 
  hexDecode,
  detectFormat,
  chainEncode 
} from '@synet/encoder';

// Simple encoding
const encoded = encode('Hello World', 'base64');
console.log(encoded); // SGVsbG8gV29ybGQ=

// Format-specific functions
const hex = hexEncode('Hello');
console.log(hex); // 48656c6c6f

// Auto-detection
const format = detectFormat('48656c6c6f');
console.log(format); // hex

// Chain operations
const chained = chainEncode('Hello', ['hex', 'base64']);
console.log(chained); // NDg2NTZjNmM2Zg==
```

## Supported Formats

| Format | Description | Example |
|--------|-------------|---------|
| `base64` | Standard Base64 (RFC 4648) | `SGVsbG8gV29ybGQ=` |
| `base64url` | URL-safe Base64 (no padding) | `SGVsbG8gV29ybGQh` |
| `hex` | Hexadecimal encoding | `48656c6c6f` |
| `uri` | URI component encoding | `Hello%20World` |
| `ascii` | ASCII text validation | `Hello World` |

## Configuration Options

```typescript
const encoder = Encoder.create({
  defaultFormat: 'base64',    // Default encoding format
  autoDetect: true,           // Enable auto-detection for decoding
  strictMode: false,          // Strict validation mode
  maxInputSize: 10 * 1024 * 1024, // 10MB input limit
  validateOutput: true        // Validate encoded output
});
```

## Unit Architecture Integration

### Teaching Capabilities

```typescript
const encoder = Encoder.create();

// Teach encoding capabilities to other units
const learner = SomeOtherUnit.create();
learner.learn([encoder.teach()]);

// Use learned capabilities
const result = learner.execute('encoder.encode', 'Hello', 'base64');
```

### Learning from Others

```typescript
// Encoder can learn from crypto units for advanced operations
const cryptoUnit = CryptoUnit.create();
encoder.learn([cryptoUnit.teach()]);

// Now has enhanced capabilities
encoder.execute('crypto.sign', data);
```

## Error Handling

The encoder follows **Doctrine #14: ERROR BOUNDARY CLARITY**:

- **Simple operations** (detect, validate) throw exceptions
- **Complex operations** (encode, decode, chain) return Result objects

```typescript
// Throws on error (simple classification)
try {
  const detection = encoder.detect('invalid-data');
} catch (error) {
  console.log('Detection failed:', error.message);
}

// Result pattern (complex validation)
const encoded = encoder.encode('data', 'base64');
if (encoded.isFailure) {
  console.log('Encoding failed:', encoded.error);
  console.log('Cause:', encoded.errorCause);
}
```

## Chain Operations

```typescript
// Sequential encoding
const result = encoder.chain('Hello', ['hex', 'base64', 'uri']);
if (result.isSuccess) {
  console.log(result.value.encoded);
  console.log(result.value.compressionRatio);
}

// Reverse decoding
const reversed = encoder.reverse(result.value.encoded, ['hex', 'base64', 'uri']);
console.log(reversed.value.decoded); // Hello
```

## Performance Features

- **Stateless operations** - No side effects, safe for concurrency
- **Immutable design** - Thread-safe by default
- **Pure functions** - Optimal for serverless environments
- **Zero allocations** - Efficient for high-throughput scenarios

## Browser Compatibility

Works in both Node.js and browser environments:

```typescript
// Automatically uses Buffer in Node.js, btoa/atob in browsers
const encoder = Encoder.create();
const encoded = encoder.encode('Hello World', 'base64');
```

## Help System

```typescript
// Get unit help
encoder.help();

// Static help
Encoder.help();

// Capability inspection
console.log(encoder.capabilities());
console.log(encoder.whoami());
```

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```typescript
import type { 
  EncodingFormat, 
  EncodingResult, 
  DecodingResult,
  DetectionResult 
} from '@synet/encoder';
```

## License

MIT

## Contributing

Part of the [Unit Architecture](https://github.com/synthetism/unit) ecosystem. See the main repository for contribution guidelines.

---
