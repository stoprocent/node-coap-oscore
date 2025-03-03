import nodeGypBuild from 'node-gyp-build'
import { OSCORE } from './oscore'
import { join } from 'path'
import EventEmitter from 'events'

export interface NodeGypBinding {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    OSCORE: { new(...args: any[]): OSCORE; prototype: any }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const binding = nodeGypBuild(join(__dirname, '../')) as NodeGypBinding
Object.setPrototypeOf(binding.OSCORE.prototype, EventEmitter.prototype);

exports.OSCORE = binding.OSCORE;
