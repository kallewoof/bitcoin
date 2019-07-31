// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_PROOF_H
#define BITCOIN_SCRIPT_PROOF_H

#include <key.h>                    // CKey
#include <serialize.h>
#include <script/interpreter.h>     // SimpleSignatureChecker
#include <script/signingprovider.h> // SigningProvider
#include <script/sign.h>            // ProduceSignature, SimpleSignatureCreator
#include <script/standard.h>        // CTxDestination
#include <outputtype.h>             // GetDestinationForKey
#include <policy/policy.h>          // for STANDARD_SCRIPT_VERIFY_FLAGS
#include <hash.h>                   // CHashWriter

namespace proof {

class privkey_unavailable_error : public std::runtime_error { public: explicit privkey_unavailable_error(const std::string& str = "Private key is not available") : std::runtime_error(str) {} };
class signing_error : public std::runtime_error { public: explicit signing_error(const std::string& str = "Sign failed") : std::runtime_error(str) {} };
class dest_unavailable_error : public std::runtime_error { public: explicit dest_unavailable_error(const std::string& str = "Destination is not available") : std::runtime_error(str) {} };

/**
 * Result codes ordered numerically by severity, so that A is reported, if A <= B and A and B are
 * two results for a verification attempt.
 */
enum Result {
    RESULT_VALID = 0,           //!< All proofs were deemed valid.
    RESULT_INCONCLUSIVE = -1,   //!< One or several of the given proofs used unknown opcodes or the scriptPubKey had an unknown witness version, perhaps due to the verifying node being outdated.
    RESULT_INCOMPLETE = -2,     //!< One or several of the given challenges had an empty proof. The prover may need some other entity to complete the proof.
    RESULT_INVALID = -3,        //!< One or more of the given proofs were invalid
    RESULT_ERROR = -4,          //!< An error was encountered
};

inline std::string ResultString(const Result r) {
    static const char *strings[] = {"ERROR", "INVALID", "INCOMPLETE", "INCONCLUSIVE", "VALID"};
    return r < -4 || r > 0 ? "???" : strings[r + 4];
}

inline Result ResultFromBool(bool success) {
    return success ? RESULT_VALID : RESULT_INVALID;
}

/**
 * Attempt to sign a message with the given destination.
 */
void SignMessageWithSigningProvider(SigningProvider* sp, const std::string& message, const CTxDestination& destination, std::vector<uint8_t>& signature_out);

/**
 * Attempt to sign a message with the given private key.
 */
void SignMessageWithPrivateKey(CKey& key, OutputType address_type, const std::string& message, std::vector<uint8_t>& signature_out);

/**
 * Determine if a signature is valid for the given message.
 */
Result VerifySignature(const std::string& message, const CTxDestination& destination, const std::vector<uint8_t>& signature);

struct Header {
    uint32_t m_flags;       //!< standard flags (1-to-1 with standard flags)
    uint8_t m_entries;      //!< Number of proof entries

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_flags);
        READWRITE(m_entries);
    }
};

struct SignatureProof {
    CScript m_scriptsig; //!< ScriptSig data
    CScriptWitness m_witness;   //!< Witness

    explicit SignatureProof(const SignatureData& sigdata = SignatureData()) {
        m_scriptsig = sigdata.scriptSig;
        m_witness = sigdata.scriptWitness;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_scriptsig);
        READWRITE(m_witness.stack);
    }
};

struct Purpose {
    template<typename T>
    Result Prepare(const T& input, std::set<T>& inputs_out) const {
        if (inputs_out.count(input)) return RESULT_ERROR;
        inputs_out.insert(input);
        return RESULT_VALID;
    }
};

/**
 * Purpose: SignMessage
 *
 * Generate a sighash based on a scriptPubKey and a message. Emits VALID on success.
 */
struct SignMessage: Purpose {
    CScript m_scriptpubkey;

    explicit SignMessage(const CScript& scriptpubkey = CScript()) : m_scriptpubkey(scriptpubkey) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(m_scriptpubkey);
    }

    Result Prepare(const std::vector<SignMessage>& entries, const std::string& message, std::set<CScript>& inputs_out, uint256& sighash_out, CScript& spk_out) const;

    inline std::set<CScript> InputsSet() { return std::set<CScript>(); }
};

struct Proof: public Header {
    std::vector<SignatureProof> m_items;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        Header::SerializationOp(s, ser_action);
        m_items.resize(m_entries);
        for (auto& e : m_items) {
            READWRITE(e);
        }
    }
};

template<typename T>
struct BaseWorkSpace {
    std::map<CTxDestination, CKey> privkeys;
    std::vector<T> m_challenge;
    Proof m_proof;

    virtual void GenerateSingleProof(const T& challenge, SigningProvider* sp, const uint256& sighash, const CScript& scriptPubKey, const std::string& message) = 0;
    virtual Result VerifySingleProof(unsigned int flags, const T& challenge, const SignatureProof& proof, const std::string& message, const uint256& sighash, const CScript& scriptPubKey) = 0;

    void Prove(const std::string& message, SigningProvider* signingProvider = nullptr) {
        m_proof.m_items.clear();
        m_proof.m_flags = STANDARD_SCRIPT_VERIFY_FLAGS;
        m_proof.m_entries = m_challenge.size();
        if (m_challenge.size() == 0) return;
        auto inputs = m_challenge.back().InputsSet();
        uint256 sighash;
        CScript scriptPubKey;
        for (auto& c : m_challenge) {
            auto r = c.Prepare(m_challenge, message, inputs, sighash, scriptPubKey);
            if (r != RESULT_VALID) {
                throw std::runtime_error("Prepare call failed (error code " + std::to_string(r) + ")");
            }
            CTxDestination destination;
            if (!ExtractDestination(scriptPubKey, destination)) {
                throw dest_unavailable_error();
            }
            CKey secret;
            if (privkeys.count(destination)) {
                secret = privkeys.at(destination);
            } else if (signingProvider) {
                auto keyid = GetKeyForDestination(*signingProvider, destination);
                if (keyid.IsNull()) {
                    throw privkey_unavailable_error("ScriptPubKey does not refer to a key (note: multisig is not yet supported)");
                }
                if (!signingProvider->GetKey(keyid, secret)) {
                    throw privkey_unavailable_error("Private key for scriptPubKey is not known");
                }
            } else {
                throw privkey_unavailable_error("Failed to obtain private key for destination");
            }
            FillableSigningProvider sp;
            sp.AddKey(secret);
            GenerateSingleProof(c, &sp, sighash, scriptPubKey, message);
        }
    }

    Result Verify(const std::string& message) {
        size_t proofs = m_proof.m_items.size();
        size_t challenges = m_challenge.size();
        if (challenges == 0) {
            throw std::runtime_error("Nothing to verify");
        }
        if (proofs != challenges) {
            // TODO: fill out vector with empty proofs if too few and get incomplete result? What to do about too many?
            throw std::runtime_error(proofs < challenges ? "Proofs missing" : "Too many proofs");
        }

        auto inputs = m_challenge.back().InputsSet();
        Result aggres = RESULT_VALID;
        for (size_t i = 0; i < proofs; ++i) {
            auto& proof = m_proof.m_items.at(i);
            if (proof.m_scriptsig.size() == 0 && proof.m_witness.stack.size() == 0) {
                if (aggres == RESULT_VALID) aggres = RESULT_INCOMPLETE;
                continue;
            }
            auto& challenge = m_challenge.at(i);
            uint256 sighash;
            CScript scriptPubKey;
            Result res = challenge.Prepare(m_challenge, message, inputs, sighash, scriptPubKey);
            if (res != RESULT_VALID) return res;
            res = VerifySingleProof(m_proof.m_flags, challenge, proof, message, sighash, scriptPubKey);
            if (res == RESULT_ERROR || res == RESULT_INVALID) return res;
            if (res < aggres) {
                aggres = res;
            }
        }
        return aggres == RESULT_VALID && m_proof.m_flags != STANDARD_SCRIPT_VERIFY_FLAGS ? RESULT_INCONCLUSIVE : aggres;
    }
};

template<typename T> struct Workspace: public BaseWorkSpace<T> {};

template<>
struct Workspace<SignMessage>: public BaseWorkSpace<SignMessage> {
    void AppendDestinationChallenge(const CTxDestination& destination) {
        auto a = GetScriptForDestination(destination);
        m_challenge.emplace_back(a);
    }
    void AppendPrivKeyChallenge(const CKey& key, OutputType address_type = OutputType::BECH32) {
        auto d = GetDestinationForKey(key.GetPubKey(), address_type);
        auto a = GetScriptForDestination(d);
        privkeys[d] = key;
        m_challenge.emplace_back(a);
    }
    void GenerateSingleProof(const SignMessage& challenge, SigningProvider* sp, const uint256& sighash, const CScript& scriptPubKey, const std::string& message) override {
        SimpleSignatureCreator sc(sighash);
        SignatureData sigdata;
        if (!ProduceSignature(*sp, sc, scriptPubKey, sigdata)) {
            throw signing_error("Failed to produce a signature");
        }
        m_proof.m_items.emplace_back(sigdata);
    }
    Result VerifySingleProof(unsigned int flags, const SignMessage& challenge, const SignatureProof& proof, const std::string& message, const uint256& sighash, const CScript& scriptPubKey) override {
        auto& scriptSig = proof.m_scriptsig;
        auto& witness = proof.m_witness;
        SimpleSignatureChecker sc(sighash);
        ScriptError serror;
        if (!VerifyScript(scriptSig, scriptPubKey, witness.stack.size() ? &witness : nullptr, flags, sc, &serror)) {
            // TODO: inconclusive check
            return RESULT_INVALID;
        }
        return RESULT_VALID;
    }
};

typedef Workspace<SignMessage> SignMessageWorkspace;

} // namespace proof

#endif // BITCOIN_SCRIPT_PROOF_H
