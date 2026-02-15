import { REPLAY_WINDOW_SIZE } from './constants';

export class ReplayWindow {
    private highestSsn: bigint = -1n;
    private window: bigint = 0n; // bitmask — bit i represents (highestSsn - i)

    isValid(ssn: bigint): boolean {
        if (ssn > this.highestSsn) {
            return true;
        }
        const diff = this.highestSsn - ssn;
        if (diff >= BigInt(REPLAY_WINDOW_SIZE)) {
            return false; // too old
        }
        // Check if bit at position `diff` is already set
        if ((this.window >> diff) & 1n) {
            return false; // duplicate
        }
        return true;
    }

    update(ssn: bigint): void {
        if (ssn > this.highestSsn) {
            const shift = ssn - this.highestSsn;
            if (shift < BigInt(REPLAY_WINDOW_SIZE)) {
                this.window = (this.window << shift) | 1n;
            } else {
                this.window = 1n;
            }
            this.highestSsn = ssn;
        } else {
            const diff = this.highestSsn - ssn;
            this.window |= (1n << diff);
        }
    }

    reinit(currentSsn: bigint): void {
        this.highestSsn = currentSsn;
        // Fill the entire window so all SSNs <= currentSsn are marked as seen.
        // This prevents replays of messages from before the restore point.
        if (currentSsn >= 0n) {
            this.window = (1n << BigInt(REPLAY_WINDOW_SIZE)) - 1n;
        } else {
            this.window = 0n;
        }
    }
}
