/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "framing_cipher.hpp"
#include <silkworm/sentry/rlpx/crypto/aes.hpp>
#include <silkworm/sentry/rlpx/crypto/sha3_hasher.hpp>
#include <silkworm/sentry/rlpx/crypto/xor.hpp>

namespace silkworm::sentry::rlpx::framing {

using namespace crypto;
using KeyMaterial = FramingCipher::KeyMaterial;
using MACHasher = crypto::Sha3Hasher;

class FramingCipherImpl {
  public:
    FramingCipherImpl(const KeyMaterial& key_material, Bytes aes_secret, Bytes mac_secret);

  private:
    static void init_mac_hashers(const KeyMaterial& key_material, ByteView mac_secret, MACHasher& egress_mac_hasher, MACHasher& ingress_mac_hasher);

    [[nodiscard]] Bytes header_mac(MACHasher& hasher, ByteView header_cipher_text);
    [[nodiscard]] Bytes frame_mac(MACHasher& hasher, ByteView frame_cipher_text);

    Bytes aes_secret_;
    Bytes mac_secret_;
    AESCipher mac_seed_cipher_;
    MACHasher egress_mac_hasher_;
    MACHasher ingress_mac_hasher_;
};

FramingCipherImpl::FramingCipherImpl(const KeyMaterial& key_material, Bytes aes_secret, Bytes mac_secret)
    : aes_secret_(std::move(aes_secret)),
      mac_secret_(std::move(mac_secret)),
      mac_seed_cipher_(mac_secret_, std::nullopt, AESCipher::Direction::kEncrypt) {
    init_mac_hashers(key_material, mac_secret_, egress_mac_hasher_, ingress_mac_hasher_);
}

static Bytes keccak256(ByteView data1, ByteView data2) {
    Sha3Hasher hasher;
    hasher.update(data1);
    hasher.update(data2);
    return hasher.hash();
}

static void make_secrets(const KeyMaterial& key_material, Bytes& aes_secret, Bytes& mac_secret) {
    auto& ephemeral_secret = key_material.ephemeral_shared_secret;
    Bytes nonce_hash = keccak256(key_material.recipient_nonce, key_material.initiator_nonce);
    Bytes shared_secret = keccak256(ephemeral_secret, nonce_hash);
    aes_secret = keccak256(ephemeral_secret, shared_secret);
    mac_secret = keccak256(ephemeral_secret, aes_secret);
}

void FramingCipherImpl::init_mac_hashers(const KeyMaterial& key_material, ByteView mac_secret, MACHasher& egress_mac_hasher, MACHasher& ingress_mac_hasher) {
    auto initiator_nonce = key_material.initiator_nonce;
    xor_bytes(initiator_nonce, mac_secret);

    auto recipient_nonce = key_material.recipient_nonce;
    xor_bytes(recipient_nonce, mac_secret);

    auto& initiator_hasher = key_material.is_initiator ? egress_mac_hasher : ingress_mac_hasher;
    auto& recipient_hasher = key_material.is_initiator ? ingress_mac_hasher : egress_mac_hasher;

    initiator_hasher.update(recipient_nonce);
    initiator_hasher.update(key_material.initiator_first_message_data);

    recipient_hasher.update(initiator_nonce);
    recipient_hasher.update(key_material.recipient_first_message_data);
}

Bytes FramingCipherImpl::header_mac(MACHasher& hasher, ByteView header_cipher_text) {
    assert(header_cipher_text.size() >= kAESBlockSize);

    auto hash = hasher.hash();
    auto header_mac_seed = mac_seed_cipher_.encrypt(ByteView(hash.data(), kAESBlockSize));
    crypto::xor_bytes(header_mac_seed, header_cipher_text);
    hasher.update(header_mac_seed);

    auto header_hash = hasher.hash();
    header_hash.resize(kAESBlockSize);
    return header_hash;
}

Bytes FramingCipherImpl::frame_mac(MACHasher& hasher, ByteView frame_cipher_text) {
    hasher.update(frame_cipher_text);

    auto hash = hasher.hash();
    auto frame_mac_seed = mac_seed_cipher_.encrypt(ByteView(hash.data(), kAESBlockSize));
    crypto::xor_bytes(frame_mac_seed, hash);
    hasher.update(frame_mac_seed);

    auto header_hash = hasher.hash();
    header_hash.resize(kAESBlockSize);
    return header_hash;
}

FramingCipher::FramingCipher(const KeyMaterial& key_material) {
    Bytes aes_secret, mac_secret;
    make_secrets(key_material, aes_secret, mac_secret);
    impl_ = std::make_unique<FramingCipherImpl>(key_material, aes_secret, mac_secret);
}

FramingCipher::~FramingCipher() {}

}  // namespace silkworm::sentry::rlpx::framing
