import { expect, describe, it, beforeEach, jest } from '@jest/globals';
import { OSCORE, OscoreContextStatus, OscoreContext } from '../dist/index';
import exp from 'constants';

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
});