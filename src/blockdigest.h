// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_SRC_BLOCKDIGEST_H_
#define _BITCOIN_SRC_BLOCKDIGEST_H_

#include <vector>
#include <boost/filesystem.hpp>

#include "bloom.h"
#include "serialize.h"
#include "uint256.h"
#include "primitives/block.h"
#include "chainparams.h"
#include "validation.h"

class COutPoint;
class CBlock;
class CTransaction;

namespace DigestFilter {

class base_filter {
public:
    virtual void insert(const std::vector<uint8_t>& data) = 0;
    virtual void clear() = 0;
    virtual bool contains(const std::vector<uint8_t>& data) const = 0;

    std::vector<uint8_t> outpoint_data(const COutPoint& outpoint) const;
    std::vector<std::vector<uint8_t>> tx_data_vec(const CTransaction& tx) const;

    void digest_block(const CBlock& block);
    void digest_tx(const CTransaction& tx);

    virtual void insert(const std::vector<std::vector<uint8_t>>& data_vec) {
        for (const std::vector<uint8_t>& d : data_vec) insert(d);
    }

    virtual bool contains(const std::vector<std::vector<uint8_t>>& data_vec) const {
        for (const std::vector<uint8_t>& d : data_vec) if (contains(d)) return true;
        return false;
    }

    virtual void insert(const COutPoint& outpoint) { insert(outpoint_data(outpoint)); }
    virtual void insert(const uint256& hash)       { insert(std::vector<uint8_t>(hash.begin(), hash.end())); }
    virtual void insert(const CTransaction& tx)    { insert(tx_data_vec(tx)); }

    virtual bool contains(const COutPoint& outpoint) const { return contains(outpoint_data(outpoint)); }
    virtual bool contains(const uint256& hash) const       { return contains(std::vector<uint8_t>(hash.begin(), hash.end())); }
    virtual bool contains(const CTransaction& tx) const    { return contains(tx_data_vec(tx)); }
};

class bloom_filter : public base_filter {
private:
    CBloomFilter filter;
public:
    using base_filter::insert;
    using base_filter::contains;

    // TODO: obtain and use # of elements instead of using hard coded 128 value
    bloom_filter() : filter(128, 0.000001, 0, BLOOM_UPDATE_ALL) {}
    virtual ~bloom_filter() {}

    void insert(const std::vector<uint8_t>& data) override;
    bool contains(const std::vector<uint8_t>& data) const override;

    void clear() override;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(filter);
    }
};

template <typename F>
class digest {
public:
    F filter;
    int32_t block_height;
    uint256 block_hash;

    bool contains(const std::vector<uint8_t>& data) { return filter.contains(data); }
    bool contains(const COutPoint& outpoint)        { return filter.contains(outpoint); }
    bool contains(const uint256& hash)              { return filter.contains(hash); }
    bool contains(const CTransaction& tx)           { return filter.contains(tx); }

    void populate(const int32_t desired_block_height)
    {
        CBlock block;
        filter.clear();
        CBlockIndex* pindex = chainActive[desired_block_height];
        block_height = pindex->nHeight;
        block_hash = pindex->phashBlock ? *pindex->phashBlock : uint256();
        const Consensus::Params& consensusParams = Params().GetConsensus();
        if (pindex) {
            if (!ReadBlockFromDisk(block, pindex, consensusParams)) {
                assert(!"cannot load block from disk");
            }
            filter.digest_block(block);
        }
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(block_height);
        READWRITE(block_hash);
        READWRITE(filter);
    }
};

}  // namespace DigestFilter

#endif  // _BITCOIN_SRC_BLOCKDIGEST_H_
