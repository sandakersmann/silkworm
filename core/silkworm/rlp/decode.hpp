/*
   Copyright 2020-2022 The Silkworm Authors

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

// RLP decoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#pragma once

#include <array>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::rlp {

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
[[nodiscard]] std::pair<Header, DecodingResult> decode_header(ByteView& from) noexcept;

template <class T>
DecodingResult decode(ByteView& from, T& to) noexcept;

template <>
DecodingResult decode(ByteView& from, evmc::bytes32& to) noexcept;

template <>
DecodingResult decode(ByteView& from, Bytes& to) noexcept;

template <UnsignedIntegral T>
DecodingResult decode(ByteView& from, T& to) noexcept {
    auto [h, err]{decode_header(from)};
    if (err != DecodingResult::kOk) {
        return err;
    }
    if (h.list) {
        return DecodingResult::kUnexpectedList;
    }
    err = endian::from_big_compact(from.substr(0, h.payload_length), to);
    if (err != DecodingResult::kOk) {
        return err;
    }
    from.remove_prefix(h.payload_length);
    return DecodingResult::kOk;
}

template <>
DecodingResult decode(ByteView& from, bool& to) noexcept;

template <size_t N>
DecodingResult decode(ByteView& from, std::span<uint8_t, N> to) noexcept {
    static_assert(N != std::dynamic_extent);

    auto [h, err]{decode_header(from)};
    if (err != DecodingResult::kOk) {
        return err;
    }
    if (h.list) {
        return DecodingResult::kUnexpectedList;
    }
    if (h.payload_length != N) {
        return DecodingResult::kUnexpectedLength;
    }

    std::memcpy(to.data(), from.data(), N);
    from.remove_prefix(N);
    return DecodingResult::kOk;
}

template <size_t N>
DecodingResult decode(ByteView& from, uint8_t (&to)[N]) noexcept {
    return decode<N>(from, std::span<uint8_t, N>{to});
}

template <size_t N>
DecodingResult decode(ByteView& from, std::array<uint8_t, N>& to) noexcept {
    return decode<N>(from, std::span<uint8_t, N>{to});
}

template <class T>
DecodingResult decode_vector(ByteView& from, std::vector<T>& to) noexcept {
    auto [h, err]{decode_header(from)};
    if (err != DecodingResult::kOk) {
        return err;
    }
    if (!h.list) {
        return DecodingResult::kUnexpectedString;
    }

    to.clear();

    ByteView payload_view{from.substr(0, h.payload_length)};
    while (!payload_view.empty()) {
        to.emplace_back();
        if (err = decode(payload_view, to.back()); err != DecodingResult::kOk) {
            return err;
        }
    }

    from.remove_prefix(h.payload_length);
    return DecodingResult::kOk;
}

template <class T>
DecodingResult decode(ByteView& from, std::vector<T>& to) noexcept {
    return decode_vector(from, to);
}

template <typename Arg1, typename Arg2>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2) noexcept {
    DecodingResult err = decode(from, arg1);
    if (err != DecodingResult::kOk)
        return err;
    return decode(from, arg2);
}

template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    DecodingResult err = decode(from, arg1);
    if (err != DecodingResult::kOk)
        return err;
    return decode_items(from, arg2, args...);
}

template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode(ByteView& from, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    auto [header, err] = decode_header(from);
    if (err != DecodingResult::kOk) {
        return err;
    }
    if (!header.list) {
        return DecodingResult::kUnexpectedString;
    }
    return decode_items(from, arg1, arg2, args...);
}

}  // namespace silkworm::rlp
