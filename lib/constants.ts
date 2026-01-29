// CoAP message types
export const TYPE_CON = 0;
export const TYPE_NON = 1;
export const TYPE_ACK = 2;
export const TYPE_RST = 3;

// CoAP code 0.00 (Empty)
export const CODE_EMPTY = 0;

// OSCORE-protected CoAP codes
export const CODE_POST = 0x02;           // 0.02 POST (used for OSCORE requests)
export const CODE_CHANGED = 0x44;        // 2.04 Changed (used for OSCORE responses)

// CoAP option numbers
export const OPTION_IF_MATCH = 1;
export const OPTION_URI_HOST = 3;
export const OPTION_ETAG = 4;
export const OPTION_IF_NONE_MATCH = 5;
export const OPTION_OBSERVE = 6;
export const OPTION_URI_PORT = 7;
export const OPTION_LOCATION_PATH = 8;
export const OPTION_OSCORE = 9;
export const OPTION_URI_PATH = 11;
export const OPTION_CONTENT_FORMAT = 12;
export const OPTION_MAX_AGE = 14;
export const OPTION_URI_QUERY = 15;
export const OPTION_ACCEPT = 17;
export const OPTION_LOCATION_QUERY = 20;
export const OPTION_BLOCK2 = 23;
export const OPTION_BLOCK1 = 27;
export const OPTION_SIZE2 = 28;
export const OPTION_PROXY_URI = 35;
export const OPTION_PROXY_SCHEME = 39;
export const OPTION_SIZE1 = 60;

// Crypto constants (AES-CCM-16-64-128 per RFC 8613)
export const AEAD_ALG_ID = 10;           // COSE Algorithm ID for AES-CCM-16-64-128
export const KEY_LEN = 16;               // 128-bit key
export const NONCE_LEN = 13;             // 13-byte nonce
export const AUTH_TAG_LEN = 8;           // 64-bit authentication tag

// SSN / PIV limits
export const MAX_SSN = 0x7FFFFF;         // max SSN that fits in 3 bytes (per typical OSCORE)
export const MAX_PIV_LEN = 5;            // maximum PIV length in bytes
export const REPLAY_WINDOW_SIZE = 32;    // sliding window size

// OSCORE option flag masks (first byte of OSCORE option value)
export const FLAG_KID = 0x08;            // bit 3: KID present
export const FLAG_KID_CTX = 0x10;        // bit 4: KID Context present
export const FLAG_PIV_MASK = 0x07;       // bits 0-2: PIV length

// Class E options (encrypted in OSCORE) per RFC 8613 Section 4.1
// These options are moved into the encrypted payload
const CLASS_E_OPTIONS = new Set<number>([
    OPTION_IF_MATCH,        // 1
    OPTION_ETAG,            // 4
    OPTION_IF_NONE_MATCH,   // 5
    OPTION_OBSERVE,         // 6
    OPTION_LOCATION_PATH,   // 8
    OPTION_URI_PATH,        // 11
    OPTION_CONTENT_FORMAT,  // 12
    OPTION_MAX_AGE,         // 14
    OPTION_URI_QUERY,       // 15
    OPTION_ACCEPT,          // 17
    OPTION_LOCATION_QUERY,  // 20
    OPTION_BLOCK2,          // 23
    OPTION_BLOCK1,          // 27
    OPTION_SIZE2,           // 28
    OPTION_SIZE1,           // 60
]);

export function isClassE(optNum: number): boolean {
    return CLASS_E_OPTIONS.has(optNum);
}

// Payload marker
export const PAYLOAD_MARKER = 0xFF;
