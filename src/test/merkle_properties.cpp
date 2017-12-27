#include "test/gen/merkle_gen.h"

#include "test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>
#include <rapidcheck/boost_test.h>

BOOST_FIXTURE_TEST_SUITE(merkle_properties, BasicTestingSetup)

/** Check CScript serialization symmetry */
RC_BOOST_PROP(merkle_node_properties, (MerkleNode node)) {
  MerkleNode n(node.GetLeft(), node.GetRight());
  RC_ASSERT(n == node);
  MerkleNode n1;
  n1.SetLeft(node.GetLeft());
  n1.SetRight(node.GetRight());
  n1.SetCode(node.GetCode());
  RC_ASSERT(node == n1); 
}

RC_BOOST_PROP(merkle_node_relational, (std::pair<MerkleNode,MerkleNode> p)) {
  const MerkleNode n1 = p.first;
  const MerkleNode n2 = p.second;
  //one of these comparisons must always evaluate to true
  RC_ASSERT((n1 == n2) || (n1 != n2));
  RC_ASSERT((n1 <= n2) || (n1 > n2));
  RC_ASSERT((n1 < n2) || (n1 >= n2));
}

RC_BOOST_PROP(merkle_proof_serialization, (MerkleProof p)) {
  CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
  ss << p;
  MerkleProof p1;
  ss >> p1;
  CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
  ss1 << p1;
  RC_ASSERT(ss.str() == ss1.str());
}

RC_BOOST_PROP(merkle_tree_serialization, (MerkleTree t)) {
  CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
  ss << t;
  MerkleTree t1;
  ss >> t1;
  CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
  ss1 << t1;
  RC_ASSERT(ss.str() == ss1.str());
}

BOOST_AUTO_TEST_SUITE_END()
