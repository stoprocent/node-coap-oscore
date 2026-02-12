import EventEmitter from 'node:events';
import {
    CODE_POST, CODE_CHANGED, OPTION_OSCORE, OPTION_OBSERVE,
    FLAG_KID, FLAG_KID_CTX, FLAG_PIV_MASK,
    PAYLOAD_MARKER,
} from './constants';
import {
    deserialize, serialize, isRequest, isEmptyAckOrRst,
    splitOptions, mergeOptions, serializeOptionsOnly,
    CoapOption,
} from './coap';
import { createAAD, createEncStructure, defaultAeadProvider, AeadProvider } from './crypto';
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
    aead?: AeadProvider;
}

export class OSCORE extends EventEmitter {
    private ctx: SecurityContext;
    private aead: AeadProvider;

    constructor(params: OscoreContext) {
        super();

        this.aead = params.aead ?? defaultAeadProvider;

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
        const { eOptions, uOptions } = splitOptions(pkt.options);

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

        // Determine if this response is a notification (has Observe in E-options)
        const isNotification = !isReq && eOptions.some(o => o.number === OPTION_OBSERVE);

        let piv: Buffer;
        let nonce: Buffer;
        let currentSsn: bigint | null;

        if (isReq || isNotification) {
            // Request or notification: generate fresh PIV, increment SSN
            piv = ssnToPiv(this.ctx.ssn);
            currentSsn = this.ctx.ssn;
            this.ctx.ssn++;

            if (isReq) {
                this.ctx.requestKid = this.ctx.senderId;
                this.ctx.requestPiv = piv;
            }

            nonce = createNonce(this.ctx.senderId, piv, this.ctx.commonIv);
        } else {
            // Normal response: reuse stored request nonce, omit PIV from OSCORE option
            piv = Buffer.alloc(0);
            currentSsn = null;
            nonce = createNonce(this.ctx.requestKid!, this.ctx.requestPiv!, this.ctx.commonIv);
        }

        // Create AAD — always uses original request's KID and PIV (RFC 8613 §5.4)
        const aad = createAAD(
            isReq ? this.ctx.senderId : this.ctx.requestKid!,
            isReq ? piv : this.ctx.requestPiv!,
        );
        const encStructure = createEncStructure(aad);

        // Encrypt
        const ciphertext = this.aead.encrypt(this.ctx.senderKey, nonce, plaintext, encStructure);

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
        if (currentSsn !== null) {
            this.emit('ssn', currentSsn);
        }

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

        // Finding 1: Requests MUST include PIV (RFC 8613 §5.4)
        if (isReq && piv === null) {
            throw new OscoreProtocolError(
                OscoreError.OSCORE_INPKT_INVALID_PIV,
                'Request missing Partial IV',
            );
        }

        // Validate KID Context for requests
        if (isReq) {
            const localKidContext = this.ctx.idContext;
            if (
                (kidContext === null) !== (localKidContext === null) ||
                (kidContext !== null && localKidContext !== null && !kidContext.equals(localKidContext))
            ) {
                throw new OscoreProtocolError(
                    OscoreError.OSCORE_KID_RECIPIENT_ID_MISMATCH,
                    'KID Context does not match',
                );
            }
        }

        // Replay protection (only for requests)
        if (isReq) {
            const reqSsn = pivToSsn(piv!);
            if (!this.ctx.replayWindow.isValid(reqSsn)) {
                throw new OscoreProtocolError(
                    OscoreError.OSCORE_REPLAY_WINDOW_PROTECTION_ERROR,
                    'Replay window protection error',
                );
            }
        }

        // Finding 3: Nonce computation per RFC 8613 §5.3
        let nonce: Buffer;
        if (isReq) {
            // Request: sender's KID + PIV from the message
            nonce = createNonce(kid!, piv!, this.ctx.commonIv);
        } else if (piv !== null) {
            // Response with PIV (notification): responder's sender ID + response PIV
            nonce = createNonce(this.ctx.recipientId, piv, this.ctx.commonIv);
        } else {
            // Response without PIV: reuse stored request nonce
            nonce = createNonce(this.ctx.requestKid!, this.ctx.requestPiv!, this.ctx.commonIv);
        }

        // Create AAD — always uses original request's KID and PIV (RFC 8613 §5.4)
        const aad = createAAD(
            isReq ? kid! : this.ctx.requestKid!,
            isReq ? piv! : this.ctx.requestPiv!,
        );
        const encStructure = createEncStructure(aad);

        // Decrypt
        let plaintext: Buffer;
        try {
            plaintext = this.aead.decrypt(this.ctx.recipientKey, nonce, pkt.payload, encStructure);
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
            this.ctx.replayWindow.update(pivToSsn(piv!));
            this.ctx.requestKid = kid!;
            this.ctx.requestPiv = piv!;
        }

        // Finding 2: Notification replay protection
        if (!isReq && piv !== null) {
            const hasObserve = eOptions.some(o => o.number === OPTION_OBSERVE);
            if (hasObserve) {
                const tokenHex = pkt.token.toString('hex');
                const notifSsn = pivToSsn(piv);
                const storedSsn = this.ctx.notificationReplay.get(tokenHex);
                if (storedSsn !== undefined && notifSsn <= storedSsn) {
                    throw new OscoreProtocolError(
                        OscoreError.OSCORE_REPLAY_NOTIFICATION_PROTECTION_ERROR,
                        'Notification replay detected',
                    );
                }
                this.ctx.notificationReplay.set(tokenHex, notifSsn);
            }
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
        // Normal responses use piv=Buffer.alloc(0) → empty OSCORE option
        // Notifications use fresh PIV → included in OSCORE option
        if (piv.length > 0) {
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
        if (offset + pivLen > value.length) {
            throw new OscoreProtocolError(OscoreError.NOT_VALID_INPUT_PACKET, 'PIV overrun');
        }
        piv = Buffer.from(value.subarray(offset, offset + pivLen));
        offset += pivLen;
    }

    let kidContext: Buffer | null = null;
    if (hasKidCtx) {
        if (offset >= value.length) {
            throw new OscoreProtocolError(OscoreError.NOT_VALID_INPUT_PACKET, 'missing KID Context length');
        }
        const kidCtxLen = value[offset++];
        if (offset + kidCtxLen > value.length) {
            throw new OscoreProtocolError(OscoreError.NOT_VALID_INPUT_PACKET, 'KID Context overrun');
        }
        kidContext = Buffer.from(value.subarray(offset, offset + kidCtxLen));
        offset += kidCtxLen;
    }

    let kid: Buffer | null = null;
    if (hasKid) {
        kid = Buffer.from(value.subarray(offset));
    }

    return { piv, kid, kidContext };
}
