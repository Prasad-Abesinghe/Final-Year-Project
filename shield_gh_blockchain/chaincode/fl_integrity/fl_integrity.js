'use strict';
const { Contract } = require('fabric-contract-api');
const crypto       = require('crypto');

class FLIntegrityContract extends Contract {

    /**
     * CommitGradientHash — Eq 3.22
     * FL vehicle client calls this BEFORE submitting gradient to aggregator.
     * Stores SHA-256 hash on chain so the aggregator can verify integrity.
     */
    async CommitGradientHash(ctx, nodeId, roundNum, gradientHash) {
        const key = `GRAD_${nodeId}_${roundNum}`;
        const existing = await ctx.stub.getState(key);
        if (existing.length > 0) {
            throw new Error(`Commitment already exists for node=${nodeId} round=${roundNum}`);
        }
        const entry = {
            nodeId,
            roundNum:  parseInt(roundNum),
            hash:      gradientHash,
            timestamp: new Date().toISOString(),
            verified:  false,
        };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(entry)));
        return JSON.stringify({ status: 'committed', key });
    }

    /**
     * VerifyGradientHash — Eq 3.22
     * FL aggregator calls this to verify received gradient matches committed hash.
     * Returns { valid: bool, reason: string }.
     */
    async VerifyGradientHash(ctx, nodeId, roundNum, receivedHash) {
        const key  = `GRAD_${nodeId}_${roundNum}`;
        const data = await ctx.stub.getState(key);
        if (data.length === 0) {
            return JSON.stringify({ valid: false, reason: 'no_commitment' });
        }
        const entry = JSON.parse(data.toString());
        const valid = entry.hash === receivedHash;

        // Update verification status on chain
        entry.verified    = valid;
        entry.verifiedAt  = new Date().toISOString();
        entry.mismatch    = !valid;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(entry)));

        return JSON.stringify({
            valid,
            reason: valid ? 'hash_match' : 'hash_mismatch_poisoning_detected',
            nodeId,
            roundNum: parseInt(roundNum),
        });
    }

    /**
     * GetGradientRecord — retrieve commitment record for audit.
     */
    async GetGradientRecord(ctx, nodeId, roundNum) {
        const key  = `GRAD_${nodeId}_${roundNum}`;
        const data = await ctx.stub.getState(key);
        return data.length > 0 ? data.toString() : JSON.stringify(null);
    }

    /**
     * FlagPoisonedGradient — explicitly blacklist a gradient submitted by an attacker.
     * Called by the aggregator when a poisoning attempt is confirmed.
     */
    async FlagPoisonedGradient(ctx, nodeId, roundNum, reason) {
        const flagKey = `POISON_FLAG_${nodeId}_${roundNum}`;
        const flag = {
            nodeId,
            roundNum:  parseInt(roundNum),
            reason,
            flaggedAt: new Date().toISOString(),
        };
        await ctx.stub.putState(flagKey, Buffer.from(JSON.stringify(flag)));
        return JSON.stringify({ status: 'flagged', nodeId, roundNum });
    }
}

module.exports = { contracts: [FLIntegrityContract] };
