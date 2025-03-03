import EventEmitter from 'node:events';

/**
 * The status of the OSCORE security context.
 */
export enum OscoreContextStatus {
    /**
     * Indicates a newly created security context with fresh cryptographic material.
     * This is the default state for newly created contexts.
     */
    Fresh = 0,
    
    /**
     * Indicates a security context that has been restored from persistent storage.
     * Used when the same context needs to be maintained across application restarts.
     */
    Restored = 1,
}

/**
 * The OSCORE security context parameters.
 */
export interface OscoreContext {
    /**
     * The master secret used for deriving encryption keys.
     * Must be securely generated and kept confidential.
     */
    masterSecret: Buffer,
    
    /**
     * The master salt used in key derivation functions.
     * Provides additional randomization for key derivation.
     */
    masterSalt: Buffer,
    
    /**
     * The identifier of the sender (this device).
     * Used in the OSCORE option and for key derivation.
     */
    senderId: Buffer,
    
    /**
     * The identifier of the recipient.
     * Used for key derivation and message verification.
     */
    recipientId: Buffer,
    
    /**
     * The ID context, which provides additional context separation.
     * Optional in the OSCORE protocol but required in this implementation.
     *
     * Use an empty Buffer (Buffer.alloc(0)) if ID context is not needed.
     */
    idContext: Buffer,
    
    /**
     * Indicates whether this context is fresh or restored from persistent storage.
     * - Fresh (0): New cryptographic material, newly established context
     * - Restored (1): Context loaded from persistent storage with existing SSN state
     * 
     * Defaults to Fresh (0) if not specified.
     */
    status?: OscoreContextStatus,
    
    /**
     * The current Sender Sequence Number (SSN).
     * Used to ensure unique nonces for each message.
     * 
     * Defaults to 0 if not specified.
     * MUST be persisted and restored for Restored contexts.
     */
    ssn?: bigint,
}

/**
 * OSCORE is a security protocol for CoAP that provides message authentication and confidentiality.
 * This class provides a TypeScript interface for the OSCORE protocol.
 */
export declare class OSCORE extends EventEmitter {
    /**
     * Creates a new OSCORE instance with the provided security context.
     * 
     * @param params - The OSCORE security context parameters
     * @throws If the provided parameters are invalid
     */
    constructor(params: OscoreContext);
    
    /**
     * Encodes a CoAP message using OSCORE protection.
     * 
     * @param coapMessage - The raw CoAP message buffer to be protected
     * @returns A Promise resolving to the OSCORE-protected message buffer
     * @throws If encoding fails or if SSN exhaustion occurs
     */
    encode: (coapMessage: Buffer) => Promise<Buffer> | never;
    
    /**
     * Decodes an OSCORE-protected message into its original CoAP form.
     * 
     * @param oscoreMessage - The OSCORE-protected message buffer to be decoded
     * @returns A Promise resolving to the original CoAP message buffer
     * @throws If authentication or decryption fails, or if replay protection detects a replayed message
     */
    decode: (oscoreMessage: Buffer) => Promise<Buffer> | never;
    
    /**
     * Registers a listener for the 'ssn' event, which fires when the Sender Sequence Number changes.
     * This is particularly useful for persisting the SSN value to maintain security across application restarts.
     * 
     * @param eventName - The name of the event ('ssn')
     * @param listener - Callback function that receives the updated SSN value
     * @returns The OSCORE instance for chaining
     */
    on: (eventName: 'ssn', listener: (ssn: bigint) => void) => this;
}

export * from './bindings';