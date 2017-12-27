#include "test/gen/merkle_gen.h"

#include "test/gen/crypto_gen.h"

#include <rapidcheck/Log.h>
#include <streams.h>
#include <utilstrencodings.h>
rc::Gen<std::pair<MerkleProof,uint256>> GenerateProof(const uint256& hash) {
  return rc::gen::map<uint256>([&hash](const uint256& skip) {
    //for now construct a tree with two leaves -- one being 'hash'
    //and then generate another random 'skip' hash
    const std::vector<uint256>& leaves = { hash, skip };
    const uint256& rootHash = ComputeFastMerkleRoot(leaves);
    MerkleNode root;
    std::vector<MerkleNode> path;
    std::vector<uint256> skips;
    path.push_back(root);
    skips.push_back(skip);
    MerkleProof proof(std::move(path),std::move(skips));
    return std::make_pair(proof,rootHash);
  });
}

rc::Gen<std::pair<CScriptWitness, CScript>> GenerateMBVScript(const uint256& hash) {
  const rc::Gen<std::pair<MerkleProof,uint256>> proof = GenerateProof(hash);
  return rc::gen::map(proof, [&hash](const std::pair<MerkleProof,uint256>& p) {
    const std::vector<unsigned char> root_hash = std::vector<unsigned char>(p.second.begin(), p.second.end());
    const MerkleProof& proof = p.first;
    CScript redeemScript = CScript() << OP_MERKLEBRANCHVERIFY;
    CDataStream ss(SER_NETWORK,PROTOCOL_VERSION);
    ss << proof;
    std::vector<unsigned char> proof_ser(ss.begin(), ss.end());
    CScriptWitness witness;
    std::vector<unsigned char> vchCount = { 0x1 };
    RC_LOG() << "xvchCount: " << HexStr(vchCount.begin(), vchCount.end()) << std::endl;
    RC_LOG() << "xvchRoot: " <<  HexStr(root_hash.begin(), root_hash.end()) << std::endl;
    RC_LOG() << "xvchProof: " << HexStr(proof_ser.begin(), proof_ser.end()) << std::endl;
    witness.stack = {
      std::vector<unsigned char>(hash.begin(), hash.end()),
      proof_ser,
      root_hash,
      vchCount,
      ToByteVector(redeemScript)
    };
    return std::make_pair(witness,redeemScript);
  });
}
