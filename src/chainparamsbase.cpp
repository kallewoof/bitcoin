// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <tinyformat.h>
#include <util/system.h>
#include <util/memory.h>

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::SIGNET = "signet";
const std::string CBaseChainParams::REGTEST = "regtest";

void SetupChainParamsBaseOptions()
{
    gArgs.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.", true, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-testnet", "Use the test chain", false, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-vbparams=deployment:start:end", "Use given start/end times for specified version bits deployment (regtest-only)", true, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-signet", "Use the signet chain. Note that the network is defined by the signet_blockscript parameter", false, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-signet_blockscript", "Blocks must satisfy the given script to be considered valid (only for -signet networks)", false, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-signet_genesisnonce", "Nonce value for use in genesis block to satisfy proof of work requirement", false, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-signet_enforcescript", "Blocks must satisfy the given script to be considered valid (this replaces -signet_blockscript, and is used for opt-in-reorg mode)", false, OptionsCategory::CHAINPARAMS);
    gArgs.AddArg("-signet_seednode", "Specify a seed node for the signet network (may be used multiple times to specify multiple seed nodes)", false, OptionsCategory::CHAINPARAMS);
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return MakeUnique<CBaseChainParams>("", 8332);
    else if (chain == CBaseChainParams::TESTNET)
        return MakeUnique<CBaseChainParams>("testnet3", 18332);
    else if (chain == CBaseChainParams::REGTEST)
        return MakeUnique<CBaseChainParams>("regtest", 18443);
    else if (chain == CBaseChainParams::SIGNET)
        return MakeUnique<CBaseChainParams>("signet", 38332);
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
    gArgs.SelectConfigNetwork(chain);
}
