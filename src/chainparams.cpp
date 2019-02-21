// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "arith_uint256.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include "chainparamsseeds.h"

bool CChainParams::IsHistoricBug(const uint256& txid, unsigned nHeight, BugType& type) const
{
    const std::pair<unsigned, uint256> key(nHeight, txid);
    std::map<std::pair<unsigned, uint256>, BugType>::const_iterator mi;

    mi = mapHistoricBugs.find (key);
    if (mi != mapHistoricBugs.end ())
    {
        type = mi->second;
        return true;
    }

    return false;
}

static CBlock CreateGenesisBlock(const CScript& genesisInputScript, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = genesisInputScript;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    /*
    arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
    std::cout << hashTarget.ToString() << '\n';
    while (UintToArith256(genesis.GetHash()) > hashTarget) ++genesis.nNonce;
    */

    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "JPMorgan Chase Moves to Be First Big U.S. Bank With Its Own Cryptocurrency.";
		const CScript genesisInputScript = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}
static CBlock CreateTestnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "OP53B is shit!";
		const CScript genesisInputScript = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1051200;
        consensus.BIP34Height = 1000000000;
        consensus.BIP34Hash = uint256S("100006c80c9a27ed62e200700b039b2cd2cad259b952653039d6770ad340d369");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 1.1 * 24 * 60 * 60; // 1.1 days
        consensus.nPowTargetSpacing = 1.5 * 60; // 1.5 minutes
        consensus.nPowTargetTimespanDigisheld = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7560; // 75% of 10080
        consensus.nMinerConfirmationWindow = 10080; // 3.5 days / nPowTargetSpacing * 4 * 0.75
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // March 8, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // March 8, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // March 8, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // March 8, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000100000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000411ef4bf4852ef1ccc00695d39a4f15255233d23535276596d020c330d5");
        consensus.nAuxpowChainId = 0x0001;
        consensus.nAuxpowStartHeight = 10;
        consensus.fStrictChainId = true;
        consensus.nLegacyBlocksBefore = 10;
        consensus.rules.reset(new Consensus::MainNetConsensus());

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0x53;
        pchMessageStart[3] = 0x48;
        nDefaultPort = 9403;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1550340000, 6742724, 0x1e0ffff0, 1, 50 * COIN);

        /*
        std::cout << "genesis.nTime = " << genesis.nTime << '\n';
	      std::cout << "genesis.nBits = " << genesis.nBits << '\n';
	      std::cout << "genesis.nNonce = " << genesis.nNonce << '\n';
	      std::cout << "genesis.GetHash = " << genesis.GetHash().ToString() << '\n';
	      std::cout << "genesis.hashMerkleRoot = " << genesis.hashMerkleRoot.GetHex() << '\n';
        */

	      consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000411ef4bf4852ef1ccc00695d39a4f15255233d23535276596d020c330d5"));
        assert(genesis.hashMerkleRoot == uint256S("0x568e1d80a26d6ba07b9148d35d5c7090f57685313960d3dc654b74ff7e9c3dd2"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.emplace_back("dnsseed.shitcoin.org", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);  // S
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,40);  // H
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,55);  // P
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        base58Prefixes[OLD_SECRET_KEY] = std::vector<unsigned char>(1,178);

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x00000411ef4bf4852ef1ccc00695d39a4f15255233d23535276596d020c330d5")},
            }
        };

    }
    int DefaultCheckNameDB () const
		{
        return -1;
    }
};

/**
 * Testnet (v4)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1051200;
        consensus.BIP34Height = 1000000000;
        consensus.BIP34Hash = uint256S("100006c80c9a27ed62e200700b039b2cd2cad259b952653039d6770ad340d369");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1.1 * 24 * 60 * 60; // 1.1 days
        consensus.nPowTargetSpacing = 1.5 * 60; // 1.5 minutes
        consensus.nPowTargetTimespanDigisheld = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 75; // 75% for testchains
        consensus.nMinerConfirmationWindow = 100; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // March 8, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // March 8, 2018
 
        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // March 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // March 8, 2018
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000006e46ef06f20778d5ce5e23188ba7ef87f9a40aa3e04e696d21e8561ac89"); //160675
				consensus.nAuxpowChainId = 0x0001;
        consensus.nAuxpowStartHeight = 10;
        consensus.fStrictChainId = true;
        consensus.nLegacyBlocksBefore = 10;
        consensus.rules.reset(new Consensus::TestNetConsensus());

        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xc0;

        /*
        // Hardfork params
        nSwitchKGWblock = 0;
        nSwitchDIGIblock = 0;
        nSwitchLyra2REv2_DGW = 0;
        */

        nDefaultPort = 19403;
        nPruneAfterHeight = 1000;
        //vAlertPubKey = ParseHex("04887665070e79d20f722857e58ec8f402733f710135521a0b63441419bf5665ba4623bed13fca0cb2338682ab2a54ad13ce07fbc81c3c2f0912a4eb8521dd3cfb");

        genesis = CreateTestnetGenesisBlock(1550750400, 2532900, 0x1e0ffff0, 1, 50 * COIN);
        
        //std::cout << "genesis.nTime = " << genesis.nTime << '\n';
	      //std::cout << "genesis.nBits = " << genesis.nBits << '\n';
	      //std::cout << "genesis.nNonce = " << genesis.nNonce << '\n';
	      //std::cout << "genesis.GetHash = " << genesis.GetHash().ToString() << '\n';
	      //std::cout << "genesis.hashMerkleRoot = " << genesis.hashMerkleRoot.GetHex() << '\n';
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000006e46ef06f20778d5ce5e23188ba7ef87f9a40aa3e04e696d21e8561ac89"));
        assert(genesis.hashMerkleRoot == uint256S("0x60ff30d05560c7b0b18881ccfbe89cf3183bdb66e409a0e0411f6e74d7fc29e6"));

        //vFixedSeeds.clear();
        //vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-dnsseed.shitcoin.org", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,100);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,117);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        base58Prefixes[OLD_SECRET_KEY] = std::vector<unsigned char>(1,239);

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x000006e46ef06f20778d5ce5e23188ba7ef87f9a40aa3e04e696d21e8561ac89")},
            }
        };


    }
    int DefaultCheckNameDB () const
		{
        return -1;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = -1; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = -1; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = -1; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 1.1 * 24 * 60 * 60; // 1.5 days
        consensus.nPowTargetSpacing = 1.5 * 60; // 1.5 minutes
        consensus.nPowTargetTimespanDigisheld = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000002");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x786be69ce270ea269691bad633f815eee0c566728e273d6ae8b1e70727b649fb");

        // Hardfork params
        nSwitchKGWblock = 20;
        nSwitchDIGIblock = 40;
        nSwitchLyra2REv2_DGW = 60;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 19403;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1547910000, 4, 0x207fffff, 1, 50 * COIN);
        
        //std::cout << "genesis.nTime = " << genesis.nTime << '\n';
	      //std::cout << "genesis.nBits = " << genesis.nBits << '\n';
	      //std::cout << "genesis.nNonce = " << genesis.nNonce << '\n';
	      //std::cout << "genesis.GetHash = " << genesis.GetHash().ToString() << '\n';
	      //std::cout << "genesis.hashMerkleRoot = " << genesis.hashMerkleRoot.GetHex() << '\n';
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x72fc4fc9f8fb4f61cfad17bfa58118af161f6b426e2c533fc1c5cd9a5cb52c42"));
        assert(genesis.hashMerkleRoot == uint256S("0x0923c8ab83e99c392c7bc27a064d34bef5a6478b65034e0346a1982dc5d67604"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x72fc4fc9f8fb4f61cfad17bfa58118af161f6b426e2c533fc1c5cd9a5cb52c42")},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,117);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        base58Prefixes[OLD_SECRET_KEY] = std::vector<unsigned char>(1,239);
    }
    int DefaultCheckNameDB () const
		{
        return -1;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
