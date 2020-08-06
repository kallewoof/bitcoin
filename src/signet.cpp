// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <signet.h>

#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/standard.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/system.h>

static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

static constexpr unsigned int BLOCK_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY;

static bool ExtractCommitmentSection(CScript& script, const Span<const uint8_t> header, std::vector<uint8_t>& result)
{
    CScript replacement;
    bool found = false;

    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    std::vector<uint8_t> pushdata;
    while (script.GetOp(pc, opcode, pushdata)) {
        if (pushdata.size() > 0) {
            if (!found && pushdata.size() > (size_t) header.size() && Span<const uint8_t>(pushdata.data(), header.size()) == header) {
                // pushdata only counts if it has the header _and_ some data
                result.clear();
                result.insert(result.end(), pushdata.begin() + header.size(), pushdata.end());
                pushdata.erase(pushdata.begin() + header.size(), pushdata.end());
                found = true;
            }
            replacement << pushdata;
        } else {
            replacement << opcode;
        }
    }

    if (found) script = replacement;
    return found;
}

static uint256 ComputeModifiedMerkleRoot(const CMutableTransaction& cb, const CBlock& block)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    leaves[0] = cb.GetHash();
    for (size_t s = 1; s < block.vtx.size(); ++s) {
        leaves[s] = block.vtx[s]->GetHash();
    }
    return ComputeMerkleRoot(std::move(leaves));
}

SignetTxs SignetTxs::Create(const CBlock& block, const CScript& challenge)
{
    CMutableTransaction tx_to_spend;
    tx_to_spend.nVersion = 0;
    tx_to_spend.nLockTime = 0;
    tx_to_spend.vin.emplace_back(COutPoint(), CScript(OP_0), 0);
    tx_to_spend.vout.emplace_back(0, challenge);

    CMutableTransaction tx_spending;
    tx_spending.nVersion = 0;
    tx_spending.nLockTime = 0;
    tx_spending.vin.emplace_back(COutPoint(), CScript(), 0);
    tx_spending.vout.emplace_back(0, CScript(OP_RETURN));

    // can't fill any other fields before extracting signet
    // responses from block coinbase tx
    {
        // find and delete signet signature
        CMutableTransaction cb(*block.vtx.at(0));

        int cidx = GetWitnessCommitmentIndex(cb);
        assert(cidx != NO_WITNESS_COMMITMENT);

        CScript& script = cb.vout.at(cidx).scriptPubKey;

        std::vector<uint8_t> data;
        bool bad = false;
        if (!ExtractCommitmentSection(script, SIGNET_HEADER, data)) {
            bad = true; // no commitment
        } else {
            try {
                VectorReader v(SER_NETWORK, INIT_PROTO_VERSION, data, 0);
                v >> tx_spending.vin[0].scriptSig;
                if (!v.empty()) v >> tx_spending.vin[0].scriptWitness.stack;
                if (!v.empty()) bad = true;
            } catch (const std::exception&) {
                bad = true;
            }
        }
        if (bad) {
            // treat deserialization problems as not providing any signature and an unspendable input
            tx_to_spend.vout[0].scriptPubKey = CScript(OP_RETURN);
            tx_spending.vin[0].scriptSig.clear();
            tx_spending.vin[0].scriptWitness.stack.clear();
        } else {
            uint256 signet_merkle = ComputeModifiedMerkleRoot(cb, block);

            data.clear();
            CVectorWriter writer(SER_NETWORK, INIT_PROTO_VERSION, data, 0);
            writer << block.nVersion;
            writer << block.hashPrevBlock;
            writer << signet_merkle;
            writer << block.nTime;
            tx_to_spend.vin[0].scriptSig << data;
        }
        tx_spending.vin[0].prevout = COutPoint(tx_to_spend.GetHash(), 0);
    }

    return {tx_to_spend, tx_spending};
}

// Signet block solution checker
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams)
{
    int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) {
        return error("CheckBlockSolution: Errors in block (no witness comittment)");
    }

    const CScript challenge(consensusParams.signet_challenge.begin(), consensusParams.signet_challenge.end());
    const SignetTxs signet_txs(block, challenge);

    const CScript& scriptSig = signet_txs.to_sign.vin[0].scriptSig;
    const CScriptWitness& witness = signet_txs.to_sign.vin[0].scriptWitness;

    if (scriptSig.empty() && witness.stack.empty()) {
        return error("CheckBlockSolution: Errors in block (block solution missing)");
    }

    TransactionSignatureChecker sigcheck(&signet_txs.to_sign, /*nIn=*/ 0, /*amount=*/ signet_txs.to_spend.vout[0].nValue);

    if (!VerifyScript(scriptSig, signet_txs.to_spend.vout[0].scriptPubKey, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, sigcheck)) {
        return error("CheckBlockSolution: Errors in block (block solution invalid)");
    }
    return true;
}
