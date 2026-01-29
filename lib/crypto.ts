import { createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';
import { encode as cborEncode } from 'cbor';
import { AEAD_ALG_ID, KEY_LEN, NONCE_LEN, AUTH_TAG_LEN } from './constants';

export function deriveKeyOrIV(
    masterSecret: Buffer,
    masterSalt: Buffer,
    id: Buffer,
    idContext: Buffer | null,
    type: 'Key' | 'IV',
    length: number,
): Buffer {
    // HKDF info structure per RFC 8613 Section 3.1:
    // info = [ id: bstr, id_context: bstr / null, alg_aead: int, type: tstr, L: uint ]
    const info = cborEncode([
        id,
        idContext && idContext.length > 0 ? idContext : null,
        AEAD_ALG_ID,
        type,
        length,
    ]);

    // HKDF-SHA-256: extract with masterSalt, expand with info
    const salt = masterSalt.length > 0 ? masterSalt : Buffer.alloc(0);
    const derived = hkdfSync('sha256', masterSecret, salt, info, length);
    return Buffer.from(derived);
}

export function createAAD(requestKid: Buffer, requestPiv: Buffer): Buffer {
    // External AAD per RFC 8613 Section 5.4:
    // aad_array = [ oscore_version: uint, algorithms: [alg_aead: int], request_kid: bstr, request_piv: bstr, options: bstr ]
    return Buffer.from(cborEncode([
        1,                      // oscore_version
        [AEAD_ALG_ID],          // algorithms array
        requestKid,             // request_kid
        requestPiv,             // request_piv
        Buffer.alloc(0),        // options (empty bstr)
    ]));
}

export function createEncStructure(aad: Buffer): Buffer {
    // COSE Encrypt0 structure per RFC 9052 Section 5.3:
    // Enc_structure = ["Encrypt0", h'', external_aad]
    return Buffer.from(cborEncode([
        'Encrypt0',
        Buffer.alloc(0),        // protected header (empty for OSCORE)
        aad,
    ]));
}

export function aesCcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
    const cipher = createCipheriv('aes-128-ccm', key, nonce, { authTagLength: AUTH_TAG_LEN });
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const encrypted = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([encrypted, tag]);
}

export function aesCcmDecrypt(key: Buffer, nonce: Buffer, ciphertextWithTag: Buffer, aad: Buffer): Buffer {
    if (ciphertextWithTag.length < AUTH_TAG_LEN) {
        throw new Error('Ciphertext too short');
    }
    const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - AUTH_TAG_LEN);
    const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - AUTH_TAG_LEN);

    const decipher = createDecipheriv('aes-128-ccm', key, nonce, { authTagLength: AUTH_TAG_LEN });
    decipher.setAuthTag(tag);
    decipher.setAAD(aad, { plaintextLength: ciphertext.length });
    const decrypted = decipher.update(ciphertext);
    decipher.final(); // throws on auth failure
    return Buffer.from(decrypted);
}
