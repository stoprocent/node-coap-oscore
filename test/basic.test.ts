import { expect, describe, it, beforeEach, jest } from '@jest/globals';
import { OSCORE, OscoreContextStatus, OscoreContext } from '../dist/index';
import { generate as generateCoap } from 'coap-packet';

describe('OSCORE', () => {
  let oscoreClient: OSCORE;
  let oscoreServer: OSCORE;
  
  // Sample test context
  const clientContext: OscoreContext = {
    masterSecret: Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex'),
    masterSalt: Buffer.from('9e7ca92223786340', 'hex'),
    senderId: Buffer.from('01', 'hex'),
    recipientId: Buffer.from('02', 'hex'),
    idContext: Buffer.from('1122334455', 'hex'),
    ssn: 0n,
    status: OscoreContextStatus.Fresh
  };

  const serverContext: OscoreContext = {
    masterSecret: Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex'),
    masterSalt: Buffer.from('9e7ca92223786340', 'hex'),
    senderId: Buffer.from('02', 'hex'),
    recipientId: Buffer.from('01', 'hex'),
    idContext: Buffer.from('1122334455', 'hex'),
    status: OscoreContextStatus.Fresh
  };

  beforeEach(() => {
    oscoreClient = new OSCORE(clientContext);
    oscoreServer = new OSCORE(serverContext);
  });

  describe('encode/decode', () => {
    it('should correctly encode and decode a CoAP message', async () => {
      // Sample CoAP message
      const originalMessage = Buffer.from('44015d1f00003974396c6f63616c686f737483747631', 'hex');
      
      // Encode the message
      const encoded = await oscoreClient.encode(originalMessage);
      expect(encoded).toBeDefined();
      
      // Decode the message
      const decoded = await oscoreServer.decode(encoded);
      expect(decoded).toEqual(originalMessage);
    });

    it('should emit SSN events when encoding', async () => {
      const ssnListener = jest.fn();
      oscoreClient.on('ssn', ssnListener);

      const message = Buffer.from('44015d1f00003974396c6f63616c686f737483747631', 'hex');
      await oscoreClient.encode(message);

      expect(ssnListener).toHaveBeenCalledTimes(1);
      expect(ssnListener.mock.calls[0][0]).toBeDefined(); // SSN value
    });

    it('should throw reply protection error when decoding the same message twice', async () => {
      const message = Buffer.from('44015d1f00003974396c6f63616c686f737483747631', 'hex');
      const oscoreBuffer = await oscoreClient.encode(message);

      await oscoreServer.decode(oscoreBuffer);
      await expect(oscoreServer.decode(oscoreBuffer)).rejects.toThrow();
    });

    it('should throw error for invalid input', async () => {
      await expect(oscoreClient.encode(Buffer.from('')))
        .rejects
        .toThrow();
    });
  });

  describe('ACK and RST message handling', () => {
    it('should not encrypt ACK messages with empty code', async () => {
      // ACK message: Type=ACK, Code=0.00(Empty), MsgID=0x1234
      // According to RFC 8613 Section 4.2, empty ACK messages should bypass OSCORE
      const ackMessage = generateCoap({
        ack: true,
        code: '0.00',
        messageId: 0x1234,
        token: Buffer.alloc(0)
      });

      // When encoding an ACK message, it should pass through unchanged
      const result = await oscoreClient.encode(ackMessage);
      
      // The result should be identical to the input (no encryption)
      expect(result).toEqual(ackMessage);
    });

    it('should not encrypt RST messages with empty code', async () => {
      // RST message: Type=RST, Code=0.00(Empty), MsgID=0x5678
      // According to RFC 8613 Section 4.2, empty RST messages should bypass OSCORE
      const rstMessage = generateCoap({
        reset: true,
        code: '0.00',
        messageId: 0x5678,
        token: Buffer.alloc(0)
      });

      // When encoding an RST message, it should pass through unchanged
      const result = await oscoreClient.encode(rstMessage);
      
      // The result should be identical to the input (no encryption)
      expect(result).toEqual(rstMessage);
    });

    it('should not encrypt ACK messages with token but empty code', async () => {
      // ACK message with token: Type=ACK, Code=0.00(Empty), with 4-byte token
      // Even with a token, if the code is empty, it should bypass OSCORE
      const ackMessageWithToken = generateCoap({
        ack: true,
        code: '0.00',
        messageId: 0xabcd,
        token: Buffer.from([0x01, 0x02, 0x03, 0x04])
      });

      const result = await oscoreClient.encode(ackMessageWithToken);
      expect(result).toEqual(ackMessageWithToken);
    });

    it('should not encrypt RST messages with token but empty code', async () => {
      // RST message with token: Type=RST, Code=0.00(Empty), with 2-byte token
      const rstMessageWithToken = generateCoap({
        reset: true,
        code: '0.00',
        messageId: 0xeffe,
        token: Buffer.from([0xaa, 0xbb])
      });

      const result = await oscoreClient.encode(rstMessageWithToken);
      expect(result).toEqual(rstMessageWithToken);
    });

    it('should not corrupt context after processing empty ACK', async () => {
      // This test ensures that sending unencrypted ACK doesn't corrupt the security context
      
      // 1. Send an unencrypted ACK
      const ackMessage = generateCoap({
        ack: true,
        code: '0.00',
        messageId: 0x1111,
        token: Buffer.alloc(0)
      });
      const ackResult = await oscoreClient.encode(ackMessage);
      expect(ackResult).toEqual(ackMessage);

      // 2. Send a normal message that should be encrypted
      const normalMessage = Buffer.from('44015d1f00003974396c6f63616c686f737483747631', 'hex');
      const encrypted = await oscoreClient.encode(normalMessage);
      expect(encrypted).not.toEqual(normalMessage);

      // 3. Decode the encrypted message on server side
      const decrypted = await oscoreServer.decode(encrypted);
      expect(decrypted).toEqual(normalMessage);
    });

    it('should not corrupt context after processing empty RST', async () => {
      // This test ensures that sending unencrypted RST doesn't corrupt the security context
      
      // 1. Send an unencrypted RST
      const rstMessage = generateCoap({
        reset: true,
        code: '0.00',
        messageId: 0x2222,
        token: Buffer.alloc(0)
      });
      const rstResult = await oscoreClient.encode(rstMessage);
      expect(rstResult).toEqual(rstMessage);

      // 2. Send a normal message that should be encrypted
      const normalMessage = Buffer.from('44015d1f00003974396c6f63616c686f737483747631', 'hex');
      const encrypted = await oscoreClient.encode(normalMessage);
      expect(encrypted).not.toEqual(normalMessage);

      // 3. Decode the encrypted message on server side
      const decrypted = await oscoreServer.decode(encrypted);
      expect(decrypted).toEqual(normalMessage);
    });

    it('should properly handle interleaved ACK and encrypted messages', async () => {
      // Real-world scenario: ACK messages interleaved with normal encrypted traffic
      
      // 1. Send encrypted message 1
      const message1 = Buffer.from('44015d1f00003974396c6f63616c686f737483747631', 'hex');
      const encrypted1 = await oscoreClient.encode(message1);
      expect(encrypted1).not.toEqual(message1);

      // 2. Send empty ACK (e.g., acknowledging a CON from the other side)
      const ackMessage = generateCoap({
        ack: true,
        code: '0.00',
        messageId: 0x3333,
        token: Buffer.alloc(0)
      });
      const ackResult = await oscoreClient.encode(ackMessage);
      expect(ackResult).toEqual(ackMessage);

      // 3. Send encrypted message 2
      const message2 = Buffer.from('44025d2000003975396c6f63616c686f737483747632', 'hex');
      const encrypted2 = await oscoreClient.encode(message2);
      expect(encrypted2).not.toEqual(message2);

      // 4. Verify both encrypted messages can be decoded correctly
      const decrypted1 = await oscoreServer.decode(encrypted1);
      expect(decrypted1).toEqual(message1);
      
      const decrypted2 = await oscoreServer.decode(encrypted2);
      expect(decrypted2).toEqual(message2);
    });
  });
});