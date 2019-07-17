// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNET_H
#define BITCOIN_SIGNET_H

#include <cstdint>
#include <vector>

class CBlock;
class CScript;
class uint256;
struct CMutableTransaction;

namespace Consensus {
struct Params;
}

constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

/**
 * Extract signature and check whether a block has a valid solution
 */
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams);

/**
 * Generate the signet hash for the given block
 *
 * The signet hash differs from the regular block hash in two places:
 * 1. It hashes a modified merkle root with the signet signature removed.
 * 2. It skips the nonce.
 */
uint256 GetSignetHash(const CBlock& block);

/**
 * Attempt to get the data for the section with the given header in the witness commitment of the block.
 *
 * Returns false if header was not found. The data (excluding the 4 byte header) is written into result if found.
 */
bool GetWitnessCommitmentSection(const CBlock& block, const uint8_t header[4], std::vector<uint8_t>& result);

/**
 * Attempt to add or update the data for the section with the given header in the witness commitment of the block.
 *
 * This operation may fail and return false, if no witness commitment exists upon call time. Returns true on success.
 */
bool SetWitnessCommitmentSection(CBlock& block, const uint8_t header[4], const std::vector<uint8_t>& data);

/**
 * The tx based equivalent of the above.
 */
bool SetWitnessCommitmentSection(CMutableTransaction& tx, const uint8_t header[4], const std::vector<uint8_t>& data);

#endif // BITCOIN_SIGNET_H
