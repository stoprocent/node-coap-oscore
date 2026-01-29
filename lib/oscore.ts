import EventEmitter from 'node:events';
import {
    CODE_POST, CODE_CHANGED, OPTION_OSCORE,
    FLAG_KID, FLAG_KID_CTX, FLAG_PIV_MASK,
    PAYLOAD_MARKER,
} from './constants';
import {
    deserialize, serialize, isRequest, isEmptyAckOrRst,
    splitOptions, mergeOptions, serializeOptionsOnly,
    CoapOption,
} from './coap';
import { createAAD, createEncStructure, aesCcmEncrypt, aesCcmDecrypt } from './crypto';
import {
    SecurityContext, initSecurityContext,
    ssnToPiv, pivToSsn, createNonce, checkSsnOverflow,
} from './context';
import { OscoreError, OscoreProtocolError } from './error';

export enum OscoreContextStatus {
    Fresh = 0,
    Restored = 1,
}

export interface OscoreContext {
    masterSecret: Buffer;
    masterSalt: Buffer;
    senderId: Buffer;
    recipientId: Buffer;
    idContext: Buffer;
    status?: OscoreContextStatus;
    ssn?: bigint;
}

export class OSCORE extends EventEmitter {
    private ctx: SecurityContext;

    constructor(params: OscoreContext) {
        super();

        const status = params.status ?? OscoreContextStatus.Fresh;
        const ssn = params.ssn ?? 0n;
        const isFresh = status === OscoreContextStatus.Fresh;

        this.ctx = initSecurityContext(
            params.masterSecret,
            params.masterSalt,
            params.senderId,
            params.recipientId,
            params.idContext,
            isFresh,
            ssn,
        );
    }

    encode = async (coapMessage: Buffer): Promise<Buffer> => {
        if (coapMessage.length === 0) {
            throw new OscoreProtocolError(OscoreError.NOT_VALID_INPUT_PACKET, 'Empty input');
        }

        const pkt = deserialize(coapMessage);

        // Per RFC 8613 §4.2: empty ACK/RST bypass OSCORE
        if (isEmptyAckOrRst(pkt)) {
            return coapMessage;
        }

        // Check SSN overflow
        checkSsnOverflow(this.ctx.ssn);

        const isReq = isRequest(pkt);
        const { eOptions, uOptions } = splitOptions(pkt.options, isReq);

        // Build plaintext: [original_code, serialized_E_options, 0xFF, payload]
        const serializedEOpts = serializeOptionsOnly(eOptions);
        const plaintextParts: Buffer[] = [Buffer.from([pkt.code])];
        if (serializedEOpts.length > 0 || pkt.payload.length > 0) {
            plaintextParts.push(serializedEOpts);
        }
        if (pkt.payload.length > 0) {
            plaintextParts.push(Buffer.from([PAYLOAD_MARKER]));
            plaintextParts.push(pkt.payload);
        }
        const plaintext = Buffer.concat(plaintextParts);

        // Generate PIV and increment SSN
        const piv = ssnToPiv(this.ctx.ssn);
        const currentSsn = this.ctx.ssn;
        this.ctx.ssn++;

        // Store request KID/PIV for use in response encode/decode
        if (isReq) {
            this.ctx.requestKid = this.ctx.senderId;
            this.ctx.requestPiv = piv;
        }

        // Create nonce
        const nonce = createNonce(this.ctx.senderId, piv, this.ctx.commonIv);

        // Create AAD — always uses original request's KID and PIV (RFC 8613 §5.4)
        const aad = createAAD(
            isReq ? this.ctx.senderId : this.ctx.requestKid!,
            isReq ? piv : this.ctx.requestPiv!,
        );
        const encStructure = createEncStructure(aad);

        // Encrypt
        const ciphertext = aesCcmEncrypt(this.ctx.senderKey, nonce, plaintext, encStructure);

        // Build OSCORE option value
        const oscoreOptionValue = buildOscoreOptionValue(
            isReq, piv, this.ctx.senderId, this.ctx.idContext,
        );

        // Build OSCORE option
        const oscoreOption: CoapOption = {
            number: OPTION_OSCORE,
            value: oscoreOptionValue,
        };

        // Assemble output options: U-options + OSCORE option
        const outOptions = [...uOptions, oscoreOption];

        // Build output packet
        const outPkt = {
            version: pkt.version,
            type: pkt.type,
            tokenLength: pkt.token.length,
            code: isReq ? CODE_POST : CODE_CHANGED,
            messageId: pkt.messageId,
            token: pkt.token,
            options: outOptions,
            payload: ciphertext,
        };

        const result = serialize(outPkt);
        this.emit('ssn', currentSsn);

        return result;
    };

    decode = async (oscoreMessage: Buffer): Promise<Buffer> => {
        if (oscoreMessage.length === 0) {
            throw new OscoreProtocolError(OscoreError.NOT_VALID_INPUT_PACKET, 'Empty input');
        }

        const pkt = deserialize(oscoreMessage);

        // Find OSCORE option
        const oscoreOpt = pkt.options.find(o => o.number === OPTION_OSCORE);
        if (!oscoreOpt) {
            throw new OscoreProtocolError(OscoreError.NOT_OSCORE_PKT, 'No OSCORE option found');
        }

        // Parse OSCORE option value
        const { piv, kid, kidContext } = parseOscoreOptionValue(oscoreOpt.value);

        // Determine if this is a request (has KID in OSCORE option) or response
        const isReq = kid !== null;

        if (isReq) {
            // Verify KID matches recipientId
            if (!kid!.equals(this.ctx.recipientId)) {
                throw new OscoreProtocolError(
                    OscoreError.OSCORE_KID_RECIPIENT_ID_MISMATCH,
                    'KID does not match recipient ID',
                );
            }
        }

        // For requests, PIV must be present
        const requestPiv = piv ?? Buffer.from([0]);
        const requestKid = kid ?? Buffer.alloc(0);
        const ssn = pivToSsn(requestPiv);

        // Replay protection (only for requests)
        if (isReq) {
            if (!this.ctx.replayWindow.isValid(ssn)) {
                throw new OscoreProtocolError(
                    OscoreError.OSCORE_REPLAY_WINDOW_PROTECTION_ERROR,
                    'Replay window protection error',
                );
            }
        }

        // Determine which ID to use for nonce:
        // Request: sender's KID from the message
        // Response: responder's Sender ID = our recipientId (RFC 8613 §5.2)
        const nonceId = isReq ? requestKid : this.ctx.recipientId;
        const nonce = createNonce(nonceId, requestPiv, this.ctx.commonIv);

        // Create AAD — always uses original request's KID and PIV (RFC 8613 §5.4)
        const aad = createAAD(
            isReq ? requestKid : this.ctx.requestKid!,
            isReq ? requestPiv : this.ctx.requestPiv!,
        );
        const encStructure = createEncStructure(aad);

        // Decrypt
        let plaintext: Buffer;
        try {
            plaintext = aesCcmDecrypt(this.ctx.recipientKey, nonce, pkt.payload, encStructure);
        } catch {
            throw new OscoreProtocolError(
                OscoreError.UNEXPECTED_RESULT_FROM_EXT_LIB,
                'Decryption failed',
            );
        }

        // Parse plaintext: [code, E_options..., 0xFF, payload...]
        if (plaintext.length < 1) {
            throw new OscoreProtocolError(OscoreError.NOT_VALID_INPUT_PACKET, 'Empty plaintext');
        }

        const originalCode = plaintext[0];
        let ptOffset = 1;

        // Parse E-options from plaintext
        const eOptions: CoapOption[] = [];
        let innerPayload = Buffer.alloc(0);
        let prevOptNum = 0;

        while (ptOffset < plaintext.length) {
            const byte = plaintext[ptOffset];
            if (byte === PAYLOAD_MARKER) {
                ptOffset++;
                innerPayload = Buffer.from(plaintext.subarray(ptOffset));
                break;
            }

            let delta = (byte >> 4) & 0x0F;
            let length = byte & 0x0F;
            ptOffset++;

            if (delta === 13) {
                delta = plaintext[ptOffset] + 13;
                ptOffset++;
            } else if (delta === 14) {
                delta = (plaintext[ptOffset] << 8 | plaintext[ptOffset + 1]) + 269;
                ptOffset += 2;
            }

            if (length === 13) {
                length = plaintext[ptOffset] + 13;
                ptOffset++;
            } else if (length === 14) {
                length = (plaintext[ptOffset] << 8 | plaintext[ptOffset + 1]) + 269;
                ptOffset += 2;
            }

            const optNum = prevOptNum + delta;
            eOptions.push({
                number: optNum,
                value: Buffer.from(plaintext.subarray(ptOffset, ptOffset + length)),
            });
            prevOptNum = optNum;
            ptOffset += length;
        }

        // Get U-options from outer packet (excluding OSCORE option)
        const uOptions = pkt.options.filter(o => o.number !== OPTION_OSCORE);

        // Merge U and E options
        const allOptions = mergeOptions(uOptions, eOptions);

        // Reconstruct original CoAP packet
        const outPkt = {
            version: pkt.version,
            type: pkt.type,
            tokenLength: pkt.token.length,
            code: originalCode,
            messageId: pkt.messageId,
            token: pkt.token,
            options: allOptions,
            payload: innerPayload,
        };

        const result = serialize(outPkt);

        // Update replay window and store request context after successful decryption
        if (isReq) {
            this.ctx.replayWindow.update(ssn);
            this.ctx.requestKid = requestKid;
            this.ctx.requestPiv = requestPiv;
        }

        this.emit('ssn', this.ctx.ssn);

        return result;
    };

    on(eventName: 'ssn', listener: (ssn: bigint) => void): this;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    on(eventName: string | symbol, listener: (...args: any[]) => void): this {
        return super.on(eventName, listener);
    }
}

function buildOscoreOptionValue(
    isReq: boolean,
    piv: Buffer,
    senderId: Buffer,
    idContext: Buffer | null,
): Buffer {
    if (!isReq) {
        // Response: flag byte with PIV only (no KID, no KID context)
        if (piv.length > 0 && !(piv.length === 1 && piv[0] === 0)) {
            const flags = piv.length & FLAG_PIV_MASK;
            return Buffer.concat([Buffer.from([flags]), piv]);
        }
        return Buffer.alloc(0);
    }

    // Request: flags + PIV + optional KID context + KID
    let flags = piv.length & FLAG_PIV_MASK;
    flags |= FLAG_KID;

    const parts: Buffer[] = [];

    if (idContext && idContext.length > 0) {
        flags |= FLAG_KID_CTX;
    }

    parts.push(Buffer.from([flags]));

    // PIV
    parts.push(piv);

    // KID context length + KID context
    if (idContext && idContext.length > 0) {
        parts.push(Buffer.from([idContext.length]));
        parts.push(idContext);
    }

    // KID (sender ID)
    parts.push(senderId);

    return Buffer.concat(parts);
}

function parseOscoreOptionValue(value: Buffer): {
    piv: Buffer | null;
    kid: Buffer | null;
    kidContext: Buffer | null;
} {
    if (value.length === 0) {
        return { piv: null, kid: null, kidContext: null };
    }

    let offset = 0;
    const flags = value[offset++];

    const pivLen = flags & FLAG_PIV_MASK;
    const hasKid = (flags & FLAG_KID) !== 0;
    const hasKidCtx = (flags & FLAG_KID_CTX) !== 0;

    let piv: Buffer | null = null;
    if (pivLen > 0) {
        piv = Buffer.from(value.subarray(offset, offset + pivLen));
        offset += pivLen;
    }

    let kidContext: Buffer | null = null;
    if (hasKidCtx) {
        const kidCtxLen = value[offset++];
        kidContext = Buffer.from(value.subarray(offset, offset + kidCtxLen));
        offset += kidCtxLen;
    }

    let kid: Buffer | null = null;
    if (hasKid) {
        kid = Buffer.from(value.subarray(offset));
    }

    return { piv, kid, kidContext };
}
