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

#pragma once

#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/rlpx/crypto/sha3_hasher.hpp>

namespace silkworm::sentry::rlpx::framing {

class FramingCipher {
  public:
    struct KeyMaterial {
        Bytes ephemeral_shared_secret;
        bool is_initiator;
        Bytes initiator_nonce;
        Bytes recipient_nonce;
        Bytes initiator_first_message_data;
        Bytes recipient_first_message_data;
    };

    explicit FramingCipher(const KeyMaterial& key_material);

  private:
    using MACHasher = crypto::Sha3Hasher;

    static void make_secrets(const KeyMaterial& key_material, Bytes& aes_secret, Bytes& mac_secret);
    static void init_mac_hashers(const KeyMaterial& key_material, ByteView mac_secret, MACHasher& egress_mac_hasher, MACHasher& ingress_mac_hasher);

    Bytes aes_secret_;
    Bytes mac_secret_;
    MACHasher egress_mac_hasher_;
    MACHasher ingress_mac_hasher_;
};

}  // namespace silkworm::sentry::rlpx::framing
