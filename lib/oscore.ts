import EventEmitter from 'node:events';

export enum OscoreContextStatus {
    Fresh = 0,
    Restored = 1,
}

export interface OscoreContext {
    masterSecret: Buffer,
    masterSalt: Buffer,
    senderId: Buffer,
    recipientId: Buffer,
    idContext: Buffer,
    status: OscoreContextStatus,
    ssn: BigInt,
}

export declare class OSCORE extends EventEmitter {
        
    constructor(params: OscoreContext);
        
    encode: (coapMessage: Buffer) => Promise<Buffer> | never;
    decode: (oscoreMessage: Buffer) => Promise<Buffer> | never;
    
    on: (eventName: 'ssn', listener: (ssn: BigInt) => void) => this;
}

export * from './bindings';