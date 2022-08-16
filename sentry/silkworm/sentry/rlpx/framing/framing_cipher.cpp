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
#include <silkworm/common/util.hpp>
#include <silkworm/sentry/rlpx/crypto/xor.hpp>

namespace silkworm::sentry::rlpx::framing {

using namespace crypto;

FramingCipher::FramingCipher(const KeyMaterial& key_material) {
    make_secrets(key_material, aes_secret_, mac_secret_);
    init_mac_hashers(key_material, mac_secret_, egress_mac_hasher_, ingress_mac_hasher_);
}

Bytes keccak256(ByteView data1, ByteView data2) {
    // TODO: unfortunate copies here, should be a hash builder instead
    Bytes data{data1};
    data += data2;
    auto hash = silkworm::keccak256(data);
    return Bytes{hash.bytes, sizeof(hash.bytes)};
}

void FramingCipher::make_secrets(const KeyMaterial& key_material, Bytes& aes_secret, Bytes& mac_secret) {
    auto& ephemeral_secret = key_material.ephemeral_shared_secret;
    Bytes nonce_hash = keccak256(key_material.recipient_nonce, key_material.initiator_nonce);
    Bytes shared_secret = keccak256(ephemeral_secret, nonce_hash);
    aes_secret = keccak256(ephemeral_secret, shared_secret);
    mac_secret = keccak256(ephemeral_secret, aes_secret);
}

void FramingCipher::init_mac_hashers(const KeyMaterial& key_material, ByteView mac_secret, MACHasher& egress_mac_hasher, MACHasher& ingress_mac_hasher) {
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

}  // namespace silkworm::sentry::rlpx::framing
