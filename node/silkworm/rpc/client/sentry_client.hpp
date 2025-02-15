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

#include <chrono>
#include <functional>
#include <memory>
#include <unordered_set>

#include <grpcpp/grpcpp.h>
#include <gsl/pointers>

#include <silkworm/common/assert.hpp>
#include <silkworm/rpc/client/call.hpp>
#include <p2psentry/sentry.grpc.pb.h>

namespace silkworm::rpc {

using PeerCountCallback = std::function<void(grpc::Status, const sentry::PeerCountReply&)>;
using NodeInfoCallback = std::function<void(grpc::Status, const types::NodeInfoReply&)>;

class SentryClient {
  public:
    virtual ~SentryClient() = default;

    virtual void peer_count(PeerCountCallback callback) = 0;
    virtual void node_info(NodeInfoCallback callback) = 0;
};

class SentryClientFactory {
  public:
    virtual ~SentryClientFactory() = default;

    virtual std::unique_ptr<SentryClient> make_sentry_client(const std::string& address_uri) = 0;
};

class RemoteSentryClient : public SentryClient {
  public:
    explicit RemoteSentryClient(grpc::CompletionQueue* queue, std::shared_ptr<grpc::Channel> channel);

    RemoteSentryClient(const RemoteSentryClient&) = delete;
    RemoteSentryClient& operator=(const RemoteSentryClient&) = delete;

    void peer_count(PeerCountCallback callback) override;
    void node_info(NodeInfoCallback callback) override;

  private:
    [[maybe_unused]] auto add_rpc(gsl::owner<AsyncCall*> rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        return requests_.emplace(rpc);
    }

    [[maybe_unused]] auto remove_rpc(gsl::owner<AsyncCall*> rpc) {
        SILKWORM_ASSERT(rpc != nullptr);
        // Trick necessary because heterogeneous lookup for std::unordered_set requires C++20
        std::unique_ptr<AsyncCall> stale_rpc{rpc};
        auto removed_count = requests_.erase(stale_rpc);
        stale_rpc.release();
        return removed_count;
    }

    grpc::CompletionQueue* queue_;
    std::unique_ptr<sentry::Sentry::Stub> stub_;
    std::unordered_set<std::unique_ptr<AsyncCall>> requests_;
};

class RemoteSentryClientFactory : public SentryClientFactory {
  public:
    explicit RemoteSentryClientFactory(grpc::CompletionQueue* queue) : queue_(queue) {}

    std::unique_ptr<SentryClient> make_sentry_client(const std::string& address_uri) override;

  private:
    grpc::CompletionQueue* queue_;
};

} // namespace silkworm::rpc
