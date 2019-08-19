// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNET_H
#define BITCOIN_SIGNET_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <consensus/params.h>

#include <stdint.h>

class CBlock;
class uint256;
class CScript;

/**
 * If true, witness commitments contain a payload equal to a Bitcoin Script solution
 * to a signet challenge as defined in the chain params.
 */
extern bool g_signet_blocks;

extern CScript g_signet_blockscript;

constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

/**
 * Check whether a block has a valid solution
 */
bool CheckBlockSolution(const uint256& signet_hash, const std::vector<uint8_t>& signature, const Consensus::Params&);

/**
 * Extract signature and check whether a block has a valid solution
 */
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams);

/**
 * Generate the signet hash for the given block
 *
 * The signet hash differs from the regular block hash in two places:
 * 1. It hashes the witness root instead of the merkle root.
 * 2. It skips the nonce.
 */
uint256 GetSignetHash(const CBlock& block);

#endif // BITCOIN_SIGNET_H
