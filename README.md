# OSCORE for Node.js

[![npm version](https://img.shields.io/npm/v/coap-oscore.svg)](https://www.npmjs.com/package/coap-oscore)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance TypeScript implementation of Object Security for Constrained RESTful Environments (OSCORE) for Node.js. This native addon is built on the robust [`uoscore-uedhoc`](https://github.com/eriptic/uoscore-uedhoc) C library, providing standards-compliant implementation of [RFC 8613](https://datatracker.ietf.org/doc/rfc8613/).

## Features

- End-to-end security for CoAP messages
- Efficient implementation as a native Node.js addon
- Full TypeScript support with comprehensive type definitions
- Secure communication with IoT and constrained devices
- Event-based sequence number tracking for robust state management

## Installation

```bash
npm install coap-oscore
```

## Usage

### Basic Client Example

```typescript
import { OSCORE, OscoreContextStatus } from 'coap-oscore';

// Create OSCORE security context
const context = {
  masterSecret: Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex'),
  masterSalt: Buffer.from('9e7ca92223786340', 'hex'),
  senderId: Buffer.from('01', 'hex'),
  recipientId: Buffer.from('02', 'hex'),
  idContext: Buffer.from('37cbf3210017a2d3', 'hex'), // Use Buffer.alloc(0) if not needed
  status: OscoreContextStatus.Fresh,
  ssn: 0n
};

// Initialize OSCORE instance
const client = new OSCORE(context);

// Track sequence number changes for persistence
client.on('ssn', (ssn: bigint) => {
  console.log('New SSN:', ssn);
  // Persist SSN to maintain security across restarts
});

// Protect a CoAP message with OSCORE
async function sendSecureMessage(coapMessage: Buffer) {
  try {
    const oscoreMessage = await client.encode(coapMessage);
    // Send the protected message
    return oscoreMessage;
  } catch (error) {
    console.error('OSCORE encoding failed:', error);
    throw error;
  }
}
```

### Basic Server Example

```typescript
import { OSCORE, OscoreContextStatus } from 'coap-oscore';

// Server-side OSCORE context
const serverContext = {
  masterSecret: Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex'),
  masterSalt: Buffer.from('9e7ca92223786340', 'hex'),
  senderId: Buffer.from('02', 'hex'),      // Note: reversed compared to client
  recipientId: Buffer.from('01', 'hex'),   // Note: reversed compared to client
  idContext: Buffer.from('37cbf3210017a2d3', 'hex'),
  status: OscoreContextStatus.Fresh
};

const server = new OSCORE(serverContext);

// Process an incoming OSCORE-protected message
async function handleSecureMessage(oscoreMessage: Buffer) {
  try {
    // Decode the OSCORE message back to CoAP
    const coapMessage = await server.decode(oscoreMessage);
    // Process the verified and decrypted CoAP message
    return coapMessage;
  } catch (error) {
    console.error('OSCORE decoding failed:', error);
    throw error;
  }
}
```

## Persistence and Replay Protection

When working with the same OSCORE context across application restarts, two important mechanisms must be implemented:

### 1. Sender Sequence Number (SSN) Persistence

You must persist and restore the Sender Sequence Number (SSN) to prevent nonce reuse:

```typescript
// Before application shutdown
const currentSsn = getCurrentSsn(); // From your SSN event handler
saveToStorage('oscore_ssn', currentSsn.toString());

// On application startup
const savedSsn = loadFromStorage('oscore_ssn');
const context = {
  // ... other parameters
  status: OscoreContextStatus.Restored,
  ssn: BigInt(savedSsn)
};
```
### 2. Echo Option for Replay Protection

Per [RFC 8613 Appendix B.1.2](https://www.rfc-editor.org/rfc/rfc8613.html#appendix-B.1.2), servers **must** implement the Echo option ([RFC 9175](https://www.rfc-editor.org/rfc/rfc9175.html)) to prevent replay attacks when using restored contexts.

Server implementation example:

```typescript
import { OSCORE, OscoreContextStatus, OscoreError } from 'coap-oscore';
// Assumes a CoAP library

async function handleSecureRequest(oscoreMessage, clientAddress) {
  try {
    const coapMessage = await server.decode(oscoreMessage);
    // If we reach here, the message was successfully verified and decrypted
    
    // Process the valid request...
    // processRequest(coapMessage);
  }
  catch (error) {
    // Check if this is a replay protection error
    if (error && error.status === OscoreError.FIRST_REQUEST_AFTER_REBOOT) {
        
      // Build a response that includes ECHO option ...
      // const response = ...
        
      // Return OSCORE-protected response with Echo challenge
      return await server.encode(response);
    }
  }
}

// Client implementation would need to handle 4.01 responses with Echo option
// by including the Echo value in subsequent requests
```

The library automatically handles the replay detection mechanism and will throw an error with `status: 201` when a replay-protected context requires the Echo option verification. This makes it easy to implement the Echo option protocol as specified in the RFC.

## API Reference

### Classes

- `OSCORE` - Main class for OSCORE operations

### Interfaces

- `OscoreContext` - Configuration for OSCORE security contexts

### Enums

- `OscoreContextStatus` - Indicates whether a context is newly created or restored

### Errors

- `OscoreError` - Enum containing error codes for OSCORE operations, including general errors (0-99) and OSCORE-specific errors (200+)

For complete API documentation, see our [TypeScript API Docs](#).

## Security Considerations

- Always persist and restore the SSN to prevent nonce reuse
- Protect master secrets appropriately for your environment
- Use cryptographically secure methods to generate key material
- Monitor the 'ssn' event to track sequence number exhaustion

## Related Projects

- [`eriptic/uoscore-uedhoc`](https://github.com/eriptic/uoscore-uedhoc) - Original C implementation of OSCORE and EDHOC
- [`stoprocent/uoscore-uedhoc`](https://github.com/stoprocent/uoscore-uedhoc) - Modified fork used by this implementation

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

This implementation follows the OSCORE specification as defined in [RFC 8613](https://datatracker.ietf.org/doc/rfc8613/). Special thanks to the developers of [`uoscore-uedhoc`](https://github.com/eriptic/uoscore-uedhoc) for their foundational work.