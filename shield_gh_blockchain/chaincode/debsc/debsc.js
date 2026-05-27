'use strict';
const { Contract } = require('fabric-contract-api');
const crypto       = require('crypto');

class DESBCContract extends Contract {

    // Submit a vehicle forwarding event to the ledger
    async SubmitForwardingEvent(ctx, nodeId, timestamp, nFwd, nRx, speedKmh, rsuId, isHandoff) {
        const nDrop    = parseInt(nRx) - parseInt(nFwd);
        const speed    = parseFloat(speedKmh);
        const rawTrust = (1.0 + parseInt(nFwd)) / (1.0 + parseInt(nFwd) + 1.0 + nDrop);
        const penalty  = Math.exp(-0.010 * (speed / 3.6) * 1.0);
        const matdTrust = rawTrust * penalty;

        // Get existing history
        const histKey   = `HISTORY_${nodeId}`;
        const histBytes = await ctx.stub.getState(histKey);
        const history   = histBytes.length > 0 ? JSON.parse(histBytes.toString()) : [];
        history.push(matdTrust);
        await ctx.stub.putState(histKey, Buffer.from(JSON.stringify(history)));

        // Eq 3.18 — mean reputation
        const reputation = history.reduce((a, b) => a + b, 0) / history.length;

        // Retrieve ZKP commitment
        const zkpKey   = `ZKP_${nodeId}`;
        const zkpBytes = await ctx.stub.getState(zkpKey);
        const zkpData  = zkpBytes.length > 0 ? JSON.parse(zkpBytes.toString()) : null;
        const zkpValid = zkpData
            ? Math.abs(zkpData.committed - parseInt(nFwd)) / Math.max(parseInt(nFwd), 1) <= 0.05
            : true;

        // Eq 3.19 — DEBSC dual-gate evaluation
        const deficit  = 1 - reputation;
        const isolated = (deficit > 0.40) && !zkpValid;

        const record = {
            nodeId,
            timestamp,
            matdTrust,
            reputation,
            reputationDeficit: deficit,
            zkpValid,
            isolated,
            totalInteractions: history.length,
            rsuId,
            isHandoff: isHandoff === 'true',
        };
        await ctx.stub.putState(`RECORD_${nodeId}`, Buffer.from(JSON.stringify(record)));
        return JSON.stringify(record);
    }

    // Store ZKP commitment from vehicle (Eq 3.29)
    async CommitForwardingProof(ctx, nodeId, committedNFwd) {
        const key = `ZKP_${nodeId}`;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify({
            committed:  parseInt(committedNFwd),
            timestamp:  new Date().toISOString(),
        })));
        return 'OK';
    }

    // Store FL gradient hash commitment (Eq 3.22)
    async CommitGradient(ctx, nodeId, roundNum, gradientHash) {
        const key = `GRAD_${nodeId}_${roundNum}`;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify({
            hash:      gradientHash,
            timestamp: new Date().toISOString(),
        })));
        return 'OK';
    }

    // Verify FL gradient (called by FL aggregator)
    async VerifyGradient(ctx, nodeId, roundNum, receivedHash) {
        const key  = `GRAD_${nodeId}_${roundNum}`;
        const data = await ctx.stub.getState(key);
        if (data.length === 0) return JSON.stringify({ valid: false, reason: 'no_commitment' });
        const stored = JSON.parse(data.toString());
        return JSON.stringify({ valid: stored.hash === receivedHash });
    }

    // Query latest record for a node
    async GetRecord(ctx, nodeId) {
        const data = await ctx.stub.getState(`RECORD_${nodeId}`);
        return data.length > 0 ? data.toString() : JSON.stringify(null);
    }

    // Query reputation history for a node
    async GetHistory(ctx, nodeId) {
        const data = await ctx.stub.getState(`HISTORY_${nodeId}`);
        return data.length > 0 ? data.toString() : JSON.stringify([]);
    }
}

module.exports = { contracts: [DESBCContract] };
