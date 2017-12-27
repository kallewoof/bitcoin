#ifndef BITCOIN_TEST_GEN_MERKLE_GEN_H
#define BITCOIN_TEST_GEN_MERKLE_GEN_H

#include "test/gen/crypto_gen.h"
#include "consensus/merkle.h"
#include "uint256.h"
#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/gen/Container.h>
#include <rapidcheck/gen/Create.h>
#include <rapidcheck/gen/Select.h>
#include <rapidcheck/Gen.h>

namespace rc {

  template<>
  struct Arbitrary<MerkleLink> {
    static Gen<MerkleLink> arbitrary() {
      const auto desc = gen::just(MerkleLink::DESCEND);
      const auto ver = gen::just(MerkleLink::VERIFY);
      const auto skip = gen::just(MerkleLink::SKIP);
      return gen::oneOf(desc,ver,skip);
    };
  };

  template<>
  struct Arbitrary<MerkleNode> {
    static Gen<MerkleNode> arbitrary() {
      return rc::gen::map<std::pair<MerkleLink,MerkleLink>>([](std::pair<MerkleLink,MerkleLink> l) {
        return MerkleNode(l.first,l.second);
      });
    };
  };
  
  template<>
  struct Arbitrary<MerkleProof> {
    static Gen<MerkleProof> arbitrary() {
      typedef std::pair<std::vector<MerkleNode>,std::vector<uint256>> t;
      return rc::gen::map<t>([](t tuple) {
        return MerkleProof(std::move(tuple.first),std::move(tuple.second)); 
      });
    };
  };

  template<>
  struct Arbitrary<MerkleTree> {
    static Gen<MerkleTree> arbitrary() {
      return rc::gen::map<MerkleProof>([](MerkleProof proof) {
        MerkleTree tree;
	tree.m_proof = proof;
	tree.m_verify = proof.m_skip;
	return tree;
      });
    };
  };
} //namespace rc

/*
  Generates an arbitrary merkle proof that has a
  VERIFY node that is the given hash. Returns the
  merkle proof and the merkle root of
  the merkle tree that the merkle proof represents
*/
rc::Gen<std::pair<MerkleProof,uint256>> GenerateProof(const uint256& hash);

rc::Gen<std::pair<CScriptWitness,CScript>> GenerateMBVScript(const uint256& hash);

#endif
