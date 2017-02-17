// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockdigest.h"
#include "streams.h"
#include "version.h"
#include "uint256.h"
#include "primitives/transaction.h"
#include "utiltime.h"
#include "utilstrencodings.h"

namespace DigestFilter {

std::vector<uint8_t> base_filter::outpoint_data(const COutPoint& outpoint) const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << outpoint;
    return std::vector<uint8_t>(stream.begin(), stream.end());
}

std::vector<const std::vector<uint8_t>> base_filter::tx_data_vec(const CTransaction& tx) const
{
    std::vector<const std::vector<uint8_t>> tx_data;
    const uint256& hash = tx.GetHash();
    printf("- adding %s\n", hash.ToString().c_str());
    tx_data.emplace_back(hash.begin(), hash.end());

    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        std::vector<uint8_t> data;
        while (pc < txout.scriptPubKey.end()) {
            opcodetype opcode;
            if (!txout.scriptPubKey.GetOp(pc, opcode, data)) break;
            if (data.size() != 0) {
                printf("- adding data: %s\n", HexStr(data).c_str());
                tx_data.emplace_back(data.begin(), data.end());
            }
        }
    }

    for (const CTxIn& txin : tx.vin) {
        tx_data.emplace_back(outpoint_data(txin.prevout));

        CScript::const_iterator pc = txin.scriptSig.begin();
        std::vector<uint8_t> data;
        while (pc < txin.scriptSig.end()) {
            opcodetype opcode;
            if (!txin.scriptSig.GetOp(pc, opcode, data)) break;
            if (data.size() != 0) {
                printf("- adding in data %s\n", HexStr(data).c_str());
            }
        }
    }
    return tx_data;
}

void base_filter::digest_tx(const CTransaction& tx)
{
    insert(tx_data_vec(tx));
}

void base_filter::digest_block(const CBlock& block)
{
    for (const CTransactionRef& tx : block.vtx) {
        insert(tx_data_vec(*tx));
    }
}

void bloom_filter::insert(const std::vector<uint8_t>& data)
{
    filter.insert(data);
}

bool bloom_filter::contains(const std::vector<uint8_t>& data) const
{
    return filter.contains(data);
}

void bloom_filter::clear()
{
    filter.clear();
}


}  // namespace DigestFilter
