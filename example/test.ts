import { OSCORE, OscoreContext, OscoreContextStatus } from '../dist/index'

let context:OscoreContext = {
    masterSecret: Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"),
    masterSalt: Buffer.from("9e7ca92223786340", "hex"),
    senderId: Buffer.from([0x04]),
    recipientId: Buffer.from([0x02]),
    idContext: Buffer.from([0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x71, 0x72]),
    status: OscoreContextStatus.Fresh,
    ssn: 0n
}

let context2:OscoreContext = {
    masterSecret: Buffer.from("0102030405060708090a0b0c0d0e0f10", "hex"),
    masterSalt: Buffer.from("9e7ca92223786340", "hex"),
    senderId: Buffer.from([0x02]),
    recipientId: Buffer.from([0x04]),
    idContext: Buffer.from([0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x71, 0x72]),
    status: OscoreContextStatus.Fresh,
    ssn: 0n
}

const coapBuffer = Buffer.from("44015d1f00003974396c6f63616c686f737483747631", "hex");

async function main() {

    try {
        const oscore = new OSCORE(context)
        const oscore2 = new OSCORE(context2)

        oscore.on('ssn', (ssn: BigInt) => {
            console.log('ssn listener 1', ssn)
        })

        const oscoreBuffer = await oscore.encode(coapBuffer)
        const decoded = await oscore2.decode(oscoreBuffer)

        console.log(coapBuffer.toString('hex'))
        console.log(oscoreBuffer.toString('hex'))
        console.log(decoded.toString('hex'))
    } catch (error) {
        console.error(error)
    }
}

main()