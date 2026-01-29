import { expect, describe, it, beforeEach, jest } from '@jest/globals';
import { OSCORE, OscoreContextStatus, OscoreContext } from '../dist/index';
import { generate as generateCoap, parse as parseCoap } from 'coap-packet';

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

  describe('known-answer vectors (request encode + response decode)', () => {
    // Context from a real device trace
    const vectorContext: OscoreContext = {
      masterSecret: Buffer.from('26b17da258f6a64eca6e11d38aa2c719', 'hex'),
      masterSalt: Buffer.from('f70a831275cc1ea5', 'hex'),
      senderId: Buffer.from('53d3e28790138e', 'hex'),
      recipientId: Buffer.from('357bc825d5d94d', 'hex'),
      idContext: Buffer.alloc(0),
      status: OscoreContextStatus.Fresh,
      ssn: 0n,
    };

    // Pre-OSCORE outgoing request (original CoAP)
    const preOscoreOutgoing = Buffer.from(
      '4802ea06e5cbfdf3c9f3f607bd00617574686f72697a6174696f6e122c89ff' +
      'a261416276326263688159010721b9c03a9354a2b4aece85a35f57c9539904' +
      'ed92e141c1e04fa8fcbe52bb3ba970e89fd8c437f8041072511d61a9c1af63' +
      '83c1f4ec8c40790be5f4346882813ba76161410a626672584080f02a3c092e' +
      '914068e1d8d47c9dc033b701fab9fc4c3e9948c2be6c9a900adec9fa777472' +
      '4036fc4b37849c9f842250fdcde9f52b45d998860111ec866c3a76616e1b00' +
      '00019c0a694b80617087410b6130613161326133613461356274634c5001bc' +
      '6ab901bc69c901000062746e6847574c20546f6f6c62746f58407223dcdff8' +
      'eaf5896759398dda23435fe630a52c64bf7715af8cffb5add0a21dd1d85ec1' +
      'c6bb52c6e583bc46fae1cfa7e9033d6822f39134e159c5a7c117d3a5',
      'hex',
    );

    // Post-OSCORE outgoing request (OSCORE-encoded)
    const postOscoreOutgoing = Buffer.from(
      '4802ea06e5cbfdf3c9f3f60799090053d3e28790138eff0fe0c226d983f7d8' +
      '30fb2049b1958f6b69fe52a1087ef2011fd342d90ad2d2d0e2740e21d169ff' +
      '1677189c9d985c82f1ffd23aaf62f2c0c3a34a78bc8f42b7721e22d91380b0' +
      'df6bdf6116e5fdf6d05628f85e5921eed0f18a96d66296fa8520006e2deb4c' +
      '012e8a6cb95688d1e8c10eaa5e678514450b0dd7ab9077cf111d8f07ed1ae7' +
      'a8794136b260e06bcbf1885e919e31628a2a4b669583dd52fee1de161402d9' +
      'de211a77c3616326f819ad87e6df4e3b109d6f869e4252ce8a120a1de30795' +
      'bbdb62794864a2081744d47097939f1cb3036042030f57d91a84cf1f152d7a' +
      'e4a60eff40e766387ca742e21142414c8dcf10c0107d81313eab482ab45846' +
      'b47753833d71e41987378fb0b51ad48fd0f565bd32626566346a81710a0e9f' +
      '289a4aa760525518c572b70b2ff460f1e6',
      'hex',
    );

    // Pre-OSCORE incoming response (OSCORE-encoded response from server)
    const preOscoreIncoming = Buffer.from(
      '6844ea06e5cbfdf3c9f3f607920100ff7806a95feca842506148a126e48319' +
      '4670af69',
      'hex',
    );

    // Post-OSCORE incoming response (decoded CoAP response)
    const postOscoreIncoming = Buffer.from(
      '6881ea06e5cbfdf3c9f3f607d8ef874af24450ff8343',
      'hex',
    );

    it('should encode a request to match known output', async () => {
      const client = new OSCORE(vectorContext);
      const encoded = await client.encode(preOscoreOutgoing);
      expect(encoded.toString('hex')).toEqual(postOscoreOutgoing.toString('hex'));
    });

    it('should decode a response to match known output', async () => {
      const client = new OSCORE(vectorContext);

      // Encode the request first to populate requestKid/requestPiv
      await client.encode(preOscoreOutgoing);

      // Now decode the server's OSCORE response
      const decoded = await client.decode(preOscoreIncoming);
      expect(decoded.toString('hex')).toEqual(postOscoreIncoming.toString('hex'));
    });

    it('should encode request then decode response in sequence', async () => {
      const client = new OSCORE(vectorContext);

      // Full round-trip: encode request, then decode response
      const encoded = await client.encode(preOscoreOutgoing);
      expect(encoded.toString('hex')).toEqual(postOscoreOutgoing.toString('hex'));

      const decoded = await client.decode(preOscoreIncoming);
      expect(decoded.toString('hex')).toEqual(postOscoreIncoming.toString('hex'));
    });
  });

  describe('ECHO option handling (RFC 9175)', () => {
    const OPTION_ECHO = 252;

    // Context for ECHO exchange vectors
    const echoContext: OscoreContext = {
      masterSecret: Buffer.from('29330cd45348fda7645b7fb088a9adc7', 'hex'),
      masterSalt: Buffer.from('37aa57d55aefab68', 'hex'),
      senderId: Buffer.from('67c86e7813ba9a', 'hex'),
      recipientId: Buffer.from('04675177ddd792', 'hex'),
      idContext: Buffer.alloc(0),
      status: OscoreContextStatus.Fresh,
      ssn: 0n,
    };

    const echoServerContext: OscoreContext = {
      masterSecret: Buffer.from('29330cd45348fda7645b7fb088a9adc7', 'hex'),
      masterSalt: Buffer.from('37aa57d55aefab68', 'hex'),
      senderId: Buffer.from('04675177ddd792', 'hex'),
      recipientId: Buffer.from('67c86e7813ba9a', 'hex'),
      idContext: Buffer.alloc(0),
      status: OscoreContextStatus.Fresh,
    };

    it('should encrypt ECHO option as inner (Class E), not outer', async () => {
      const client = new OSCORE(echoContext);

      // Build a CoAP POST request with an ECHO option (252)
      const echoValue = Buffer.from('018bb5076c5a7574', 'hex');
      const original = generateCoap({
        code: '0.02',
        messageId: 0x1234,
        token: Buffer.from([0x01]),
        options: [
          { name: 'Uri-Path', value: Buffer.from('test') },
          { name: '252', value: echoValue },
        ],
        payload: Buffer.from('hello'),
      });

      const encoded = await client.encode(original);

      // Parse the outer OSCORE message — ECHO (252) must NOT be in outer options
      const outer = parseCoap(encoded);
      const outerEcho = outer.options?.find(
        (o: { name: string | number }) => String(o.name) === '252',
      );
      expect(outerEcho).toBeUndefined();
    });

    it('should preserve ECHO option through encode/decode round-trip', async () => {
      const client = new OSCORE(echoContext);
      const server = new OSCORE(echoServerContext);

      const echoValue = Buffer.from('018bb5076c5a7574', 'hex');
      const original = generateCoap({
        code: '0.02',
        messageId: 0x5678,
        token: Buffer.from([0x02]),
        options: [
          { name: 'Uri-Path', value: Buffer.from('test') },
          { name: '252', value: echoValue },
        ],
        payload: Buffer.from('hello'),
      });

      const encoded = await client.encode(original);
      const decoded = await server.decode(encoded);

      // The decoded message must contain the ECHO option with the original value
      const decodedPkt = parseCoap(decoded);
      const decodedEcho = decodedPkt.options?.find(
        (o: { name: string | number }) => String(o.name) === '252',
      );
      expect(decodedEcho).toBeDefined();
      expect(Buffer.from(decodedEcho!.value).toString('hex')).toEqual(
        echoValue.toString('hex'),
      );
    });

    it('should decode ECHO challenge response from known vector', async () => {
      const client = new OSCORE(echoContext);

      // Encode any request at SSN=0 to set up requestKid/requestPiv
      const dummyRequest = generateCoap({
        code: '0.02',
        messageId: 0xa564,
        token: Buffer.from('cf5273248a3ac760', 'hex'),
        payload: Buffer.from('test'),
      });
      await client.encode(dummyRequest);

      // ECHO challenge response from server (OSCORE-encoded)
      const echoResponse = Buffer.from(
        '6844a564cf5273248a3ac760920100ff' +
        '7f6bae0d7ed90056915c72d25c0c13d5cf200c',
        'hex',
      );

      // Must decrypt without throwing
      const decoded = await client.decode(echoResponse);
      expect(decoded.length).toBeGreaterThan(0);

      // Decoded response should contain an ECHO option (252)
      const decodedPkt = parseCoap(decoded);
      const echoOpt = decodedPkt.options?.find(
        (o: { name: string | number }) => String(o.name) === '252',
      );
      expect(echoOpt).toBeDefined();
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