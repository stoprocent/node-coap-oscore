import { KEY_LEN, NONCE_LEN, MAX_SSN, MAX_PIV_LEN, MAX_SENDER_ID_LEN } from './constants';
import { deriveKeyOrIV } from './crypto';
import { ReplayWindow } from './replay-window';
import { OscoreError } from './error';
import { OscoreProtocolError } from './error';

export interface SecurityContext {
    senderId: Buffer;
    recipientId: Buffer;
    senderKey: Buffer;
    recipientKey: Buffer;
    commonIv: Buffer;
    idContext: Buffer | null;
    ssn: bigint;
    replayWindow: ReplayWindow;
    interactions: Map<string, InteractionState>;
}

export interface InteractionState {
    requestKid: Buffer;
    requestPiv: Buffer;
    observeRequestKid: Buffer | null;
    observeRequestPiv: Buffer | null;
    notificationSsn: bigint | null;
}

export function initSecurityContext(
    masterSecret: Buffer,
    masterSalt: Buffer,
    senderId: Buffer,
    recipientId: Buffer,
    idContext: Buffer,
    isFresh: boolean,
    ssn: bigint,
): SecurityContext {
    const ctx = idContext.length > 0 ? idContext : null;

    const senderKey = deriveKeyOrIV(masterSecret, masterSalt, senderId, ctx, 'Key', KEY_LEN);
    const recipientKey = deriveKeyOrIV(masterSecret, masterSalt, recipientId, ctx, 'Key', KEY_LEN);
    // Common IV is derived with empty ID (sender_id = empty bstr)
    const commonIv = deriveKeyOrIV(masterSecret, masterSalt, Buffer.alloc(0), ctx, 'IV', NONCE_LEN);

    const replayWindow = new ReplayWindow();
    if (!isFresh && ssn > 0n) {
        replayWindow.reinit(ssn);
    }

    return {
        senderId,
        recipientId,
        senderKey,
        recipientKey,
        commonIv,
        idContext: ctx,
        ssn,
        replayWindow,
        interactions: new Map(),
    };
}

export function ssnToPiv(ssn: bigint): Buffer {
    if (ssn === 0n) {
        return Buffer.from([0]);
    }
    // Encode SSN as minimal big-endian bytes
    const bytes: number[] = [];
    let val = ssn;
    while (val > 0n) {
        bytes.unshift(Number(val & 0xFFn));
        val >>= 8n;
    }
    return Buffer.from(bytes);
}

export function pivToSsn(piv: Buffer): bigint {
    let ssn = 0n;
    for (let i = 0; i < piv.length; i++) {
        ssn = (ssn << 8n) | BigInt(piv[i]);
    }
    return ssn;
}

export function createNonce(idPiv: Buffer, piv: Buffer, commonIv: Buffer): Buffer {
    // Nonce construction per RFC 8613 Section 5.2:
    // nonce = pad_to_13_bytes(len(id) || id_padded_to_7 || piv_padded_to_5) XOR common_iv
    if (idPiv.length > MAX_SENDER_ID_LEN) {
        throw new OscoreProtocolError(OscoreError.OSCORE_INPKT_INVALID_PIV, 'Sender ID too long');
    }
    if (piv.length > MAX_PIV_LEN) {
        throw new OscoreProtocolError(OscoreError.OSCORE_INPKT_INVALID_PIV, 'PIV too long');
    }
    const nonce = Buffer.alloc(NONCE_LEN);

    // First byte: length of idPiv
    nonce[0] = idPiv.length;

    // Bytes 1-7: idPiv left-padded to fill positions such that it ends at byte 7
    // (7 bytes available for ID, starting at index 1)
    const idStart = 1 + (7 - idPiv.length);
    idPiv.copy(nonce, idStart);

    // Bytes 8-12: PIV left-padded to fill positions such that it ends at byte 12
    // (5 bytes available for PIV, starting at index 8)
    const pivStart = 8 + (5 - piv.length);
    piv.copy(nonce, pivStart);

    // XOR with common IV
    for (let i = 0; i < NONCE_LEN; i++) {
        nonce[i] ^= commonIv[i];
    }

    return nonce;
}

export function checkSsnOverflow(ssn: bigint): void {
    if (ssn > BigInt(MAX_SSN)) {
        throw new OscoreProtocolError(OscoreError.OSCORE_SSN_OVERFLOW, 'SSN overflow');
    }
}
