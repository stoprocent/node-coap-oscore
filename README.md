# OSCORE for Node.js 

A TypeScript Node.js library implemented as a native addon, built on top of the C library [`uoscore-uedhoc`](https://github.com/eriptic/uoscore-uedhoc). It provides an efficient and lightweight way to use the Object Security for Constrained RESTful Environments (OSCORE) protocol, as specified in [RFC 8613](https://datatracker.ietf.org/doc/rfc8613/).

## Installation

```bash
npm install oscore
```

## Usage

### Basic Example - Client

```typescript
import { OSCORE, OscoreContextStatus } from 'oscore';

// Create OSCORE context
const context = {
  masterSecret: Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex'),
  masterSalt: Buffer.from('9e7ca92223786340', 'hex'),
  senderId: Buffer.from('01', 'hex'),
  recipientId: Buffer.from('02', 'hex'),
  idContext: Buffer.from('37cbf3210017a2d3', 'hex'),
  status: OscoreContextStatus.Fresh,
  ssn: 0n
};

// Initialize OSCORE instance
const client = new OSCORE(context);

// Listen for SSN updates
client.on('ssn', (ssn: bigint) => {
  console.log('New SSN:', ssn);
});

// Protect a CoAP message with OSCORE
async function protect(coapMessage: Buffer) {
  try {
    const oscoreMessage = await client.encode(coapMessage);
    console.log('OSCORE message:', oscoreMessage);
    return oscoreMessage;
  } catch (error) {
    console.error('Encoding error:', error);
  }
}

// Unprotect an OSCORE message to retrieve the original CoAP message
async function unprotect(oscoreMessage: Buffer) {
  try {
    const coapMessage = await client.decode(oscoreMessage);
    console.log('CoAP message:', coapMessage);
    return coapMessage;
  } catch (error) {
    console.error('Decoding error:', error);
  }
}
```

For more detailed examples and API documentation, please refer to our [API Documentation](#).

## Documentation

For detailed documentation, refer to:

- [OSCORE Specification (RFC 8613)](https://datatracker.ietf.org/doc/rfc8613/)
- [API Documentation](#) *(TODO: Add link to generated API docs if available)*

## Contributing

We welcome contributions! To contribute:

1. Fork the repository and create a new branch.
2. Implement your feature or bug fix.
3. Write tests if applicable.
4. Open a pull request.

Please ensure your code follows the project's style and structure.

## License

This project is licensed under the [MIT License](LICENSE).

## Related Projects

- [`eriptic/uoscore-uedhoc`](https://github.com/eriptic/uoscore-uedhoc) - Lightweight C implementation of OSCORE (RFC 8613) and EDHOC (RFC 9528).
- [`stoprocent/uoscore-uedhoc`](https://github.com/stoprocent/uoscore-uedhoc) - Fork of `uoscore-uedhoc` with modifications required for this implementation.

## Acknowledgments

This implementation is based on the OSCORE specification as defined in [RFC 8613](https://datatracker.ietf.org/doc/rfc8613/). Special thanks to the developers of [`uoscore-uedhoc`](https://github.com/eriptic/uoscore-uedhoc) for their foundational work on OSCORE in C.

