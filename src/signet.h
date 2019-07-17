// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNET_H
#define BITCOIN_SIGNET_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>
#include <array>

#include <span.h>

/**
 * Extract signature and check whether a block has a valid solution
 */
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams);

/**
 * Generate the signet tx corresponding to the given block
 *
 * The signet tx commits to everything in the block except:
 * 1. It hashes a modified merkle root with the signet signature removed.
 * 2. It skips the nonce.
 */
class SignetTxs {
private:
    template<class T1, class T2>
    SignetTxs(const T1& to_spend_, const T2& to_sign_) : to_spend{to_spend_}, to_sign{to_sign_} { }

    static SignetTxs Create(const CBlock& block, const CScript& challenge);

public:
    SignetTxs(const CBlock& block, const CScript& challenge) : SignetTxs(Create(block, challenge)) { }

    CTransaction to_spend;
    CTransaction to_sign;
};

#endif // BITCOIN_SIGNET_H
