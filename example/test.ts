import { OSCORE, OscoreContext, OscoreContextStatus } from '../dist/index'

let context:OscoreContext = {
    masterSecret: Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]),
    masterSalt: Buffer.from([0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40]),
    senderId: Buffer.from([0x11]),
    recipientId: Buffer.from([0x22]),
    idContext: Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
    status: OscoreContextStatus.Fresh,
    ssn: 100n
}

const coapBuffer = Buffer.from("5802000274104545381b6a8961ffffbf61690a617abf6474696d651b00000180091a045fffff", "hex");

async function main() {

    const oscore = new OSCORE(context)

    oscore.on('ssn', (ssn: BigInt) => {
        console.log('ssn listener 1', ssn)
    })

    const oscoreBuffer = await oscore.encode(coapBuffer)

    console.log(oscoreBuffer)
}

main()