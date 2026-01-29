import {
    TYPE_ACK, TYPE_RST, CODE_EMPTY,
    OPTION_OSCORE, PAYLOAD_MARKER, isClassE,
} from './constants';

export interface CoapOption {
    number: number;
    value: Buffer;
}

export interface CoapPacket {
    version: number;
    type: number;
    tokenLength: number;
    code: number;
    messageId: number;
    token: Buffer;
    options: CoapOption[];
    payload: Buffer;
}

export function deserialize(buf: Buffer): CoapPacket {
    if (buf.length < 4) {
        throw new Error('CoAP message too short');
    }

    const byte0 = buf[0];
    const version = (byte0 >> 6) & 0x03;
    const type = (byte0 >> 4) & 0x03;
    const tokenLength = byte0 & 0x0F;
    const code = buf[1];
    const messageId = buf.readUInt16BE(2);

    if (tokenLength > 8) {
        throw new Error('Invalid token length');
    }

    if (buf.length < 4 + tokenLength) {
        throw new Error('CoAP message truncated at token');
    }

    const token = buf.subarray(4, 4 + tokenLength);
    let offset = 4 + tokenLength;

    const options: CoapOption[] = [];
    let prevOptNum = 0;

    while (offset < buf.length) {
        const byte = buf[offset];

        if (byte === PAYLOAD_MARKER) {
            offset++;
            break;
        }

        let delta = (byte >> 4) & 0x0F;
        let length = byte & 0x0F;
        offset++;

        if (delta === 13) {
            if (offset >= buf.length) throw new Error('Option delta truncated');
            delta = buf[offset] + 13;
            offset++;
        } else if (delta === 14) {
            if (offset + 1 >= buf.length) throw new Error('Option delta truncated');
            delta = buf.readUInt16BE(offset) + 269;
            offset += 2;
        } else if (delta === 15) {
            throw new Error('Invalid option delta 15');
        }

        if (length === 13) {
            if (offset >= buf.length) throw new Error('Option length truncated');
            length = buf[offset] + 13;
            offset++;
        } else if (length === 14) {
            if (offset + 1 >= buf.length) throw new Error('Option length truncated');
            length = buf.readUInt16BE(offset) + 269;
            offset += 2;
        } else if (length === 15) {
            throw new Error('Invalid option length 15');
        }

        if (offset + length > buf.length) {
            throw new Error('Option value truncated');
        }

        const optNum = prevOptNum + delta;
        options.push({
            number: optNum,
            value: Buffer.from(buf.subarray(offset, offset + length)),
        });
        prevOptNum = optNum;
        offset += length;
    }

    const payload = offset < buf.length ? Buffer.from(buf.subarray(offset)) : Buffer.alloc(0);

    return { version, type, tokenLength, code, messageId, token: Buffer.from(token), options, payload };
}

export function serialize(pkt: CoapPacket): Buffer {
    const parts: Buffer[] = [];

    // Header: 4 bytes
    const header = Buffer.alloc(4);
    header[0] = ((pkt.version & 0x03) << 6) | ((pkt.type & 0x03) << 4) | (pkt.token.length & 0x0F);
    header[1] = pkt.code;
    header.writeUInt16BE(pkt.messageId, 2);
    parts.push(header);

    // Token
    if (pkt.token.length > 0) {
        parts.push(pkt.token);
    }

    // Options (must be sorted by option number)
    const sorted = [...pkt.options].sort((a, b) => a.number - b.number);
    let prevOptNum = 0;
    for (const opt of sorted) {
        const delta = opt.number - prevOptNum;
        const optBuf = encodeOption(delta, opt.value);
        parts.push(optBuf);
        prevOptNum = opt.number;
    }

    // Payload
    if (pkt.payload.length > 0) {
        parts.push(Buffer.from([PAYLOAD_MARKER]));
        parts.push(pkt.payload);
    }

    return Buffer.concat(parts);
}

function encodeOption(delta: number, value: Buffer): Buffer {
    const parts: number[] = [];
    let nibbleDelta: number;
    const extDelta: number[] = [];

    if (delta < 13) {
        nibbleDelta = delta;
    } else if (delta < 269) {
        nibbleDelta = 13;
        extDelta.push(delta - 13);
    } else {
        nibbleDelta = 14;
        const val = delta - 269;
        extDelta.push((val >> 8) & 0xFF);
        extDelta.push(val & 0xFF);
    }

    let nibbleLen: number;
    const extLen: number[] = [];

    if (value.length < 13) {
        nibbleLen = value.length;
    } else if (value.length < 269) {
        nibbleLen = 13;
        extLen.push(value.length - 13);
    } else {
        nibbleLen = 14;
        const val = value.length - 269;
        extLen.push((val >> 8) & 0xFF);
        extLen.push(val & 0xFF);
    }

    parts.push((nibbleDelta << 4) | nibbleLen);
    parts.push(...extDelta);
    parts.push(...extLen);

    const optHeader = Buffer.from(parts);
    return Buffer.concat([optHeader, value]);
}

export function isRequest(pkt: CoapPacket): boolean {
    // Code class is upper 3 bits (code >> 5). Class 0 = requests.
    return (pkt.code >> 5) === 0 && pkt.code !== CODE_EMPTY;
}

export function isEmptyAckOrRst(pkt: CoapPacket): boolean {
    return (pkt.type === TYPE_ACK || pkt.type === TYPE_RST) && pkt.code === CODE_EMPTY;
}

export function splitOptions(options: CoapOption[]): { eOptions: CoapOption[]; uOptions: CoapOption[] } {
    const eOptions: CoapOption[] = [];
    const uOptions: CoapOption[] = [];

    for (const opt of options) {
        if (opt.number === OPTION_OSCORE) {
            // OSCORE option itself goes into U-options (it's the signaling option)
            continue;
        }
        if (isClassE(opt.number)) {
            eOptions.push(opt);
        } else {
            uOptions.push(opt);
        }
    }

    return { eOptions, uOptions };
}

export function mergeOptions(uOptions: CoapOption[], eOptions: CoapOption[]): CoapOption[] {
    // Merge and sort by option number, filtering out the OSCORE option
    const all = [...uOptions, ...eOptions].filter(o => o.number !== OPTION_OSCORE);
    all.sort((a, b) => a.number - b.number);
    return all;
}

export function serializeOptionsOnly(options: CoapOption[]): Buffer {
    const sorted = [...options].sort((a, b) => a.number - b.number);
    const parts: Buffer[] = [];
    let prevOptNum = 0;
    for (const opt of sorted) {
        const delta = opt.number - prevOptNum;
        parts.push(encodeOption(delta, opt.value));
        prevOptNum = opt.number;
    }
    return Buffer.concat(parts);
}
