// Copyright 2026 Guowei Ling.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <algorithm>
#include <chrono>
#include <future>
#include <iostream>
#include <vector>

#include "examples/fastpsi/bokvsv2.h"
#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"

using namespace yacl::crypto;
using namespace std;

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<uint128_t> FastPsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, OKVSBKV2& ourokvs) {
  uint128_t okvssize = ourokvs.getM();
  const auto t0 = std::chrono::steady_clock::now();

  // VOLE
  const auto codetype = yacl::crypto::CodeType::ExAcc7;
  std::vector<uint128_t> a(okvssize);
  std::vector<uint128_t> c(okvssize);
  auto volereceiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(ctx, absl::MakeSpan(a), absl::MakeSpan(c));
  });

  // Encode
  ourokvs.Encode(elem_hashes, elem_hashes);
  std::vector<uint128_t> aprime(okvssize);
  volereceiver.get();
  const auto t1 = std::chrono::steady_clock::now();

  yacl::parallel_for(0, aprime.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aprime[idx] = a[idx] ^ ourokvs.p_[idx];
    }
  });

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(aprime.data(), aprime.size() * sizeof(uint128_t)),
      "Send A' = P+A");
  const auto t2 = std::chrono::steady_clock::now();
  std::vector<uint128_t> receivermasks(elem_hashes.size());
  ourokvs.DecodeOtherP(elem_hashes, receivermasks, c);
  const auto t3 = std::chrono::steady_clock::now();
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  YACL_ENFORCE(buf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(sendermasks.data(), buf.data(), buf.size());
  const auto t4 = std::chrono::steady_clock::now();
  std::vector<uint128_t> receiver_sorted = std::move(receivermasks);
  std::sort(receiver_sorted.begin(), receiver_sorted.end());
  receiver_sorted.erase(
      std::unique(receiver_sorted.begin(), receiver_sorted.end()),
      receiver_sorted.end());

  auto reduce_f = [&](int64_t begin, int64_t end) {
    std::vector<uint128_t> local;
    local.reserve(static_cast<size_t>(end - begin));
    for (int64_t idx = begin; idx < end; ++idx) {
      if (std::binary_search(receiver_sorted.begin(), receiver_sorted.end(),
                             sendermasks[idx])) {
        local.push_back(elem_hashes[idx]);
      }
    }
    return local;
  };
  auto combine_f = [](std::vector<uint128_t> a, std::vector<uint128_t> b) {
    if (a.size() < b.size()) {
      a.swap(b);
    }
    a.insert(a.end(), b.begin(), b.end());
    return a;
  };
  auto intersection = yacl::parallel_reduce<std::vector<uint128_t>>(
      0, sendermasks.size(), 8192, reduce_f, combine_f);
  const auto t5 = std::chrono::steady_clock::now();

  auto ms = [](auto start, auto end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
        .count();
  };
  std::cout << "[Recv] VOLE+Encode: " << ms(t0, t1) << " ms" << std::endl;
  std::cout << "[Recv] A' compute+send: " << ms(t1, t2) << " ms" << std::endl;
  std::cout << "[Recv] Decode masks: " << ms(t2, t3) << " ms" << std::endl;
  std::cout << "[Recv] Recv masks: " << ms(t3, t4) << " ms" << std::endl;
  std::cout << "[Recv] Intersection: " << ms(t4, t5) << " ms" << std::endl;
  return intersection;
}

void FastPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& elem_hashes,
                 const OKVSBKV2& ourokvs) {
  uint128_t okvssize = ourokvs.getM();
  const auto t0 = std::chrono::steady_clock::now();
  const auto codetype = yacl::crypto::CodeType::ExAcc7;
  std::vector<uint128_t> b(okvssize);
  uint128_t delta = 0;
  auto volesender = std::async([&] {
    auto sv_sender = yacl::crypto::SilentVoleSender(codetype);
    sv_sender.Send(ctx, absl::MakeSpan(b));
    delta = sv_sender.GetDelta();
  });
  volesender.get();
  const auto t1 = std::chrono::steady_clock::now();
  std::vector<uint128_t> aprime(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive A' = P+A");
  YACL_ENFORCE(buf.size() == int64_t(okvssize * sizeof(uint128_t)));
  std::memcpy(aprime.data(), buf.data(), buf.size());
  const auto t2 = std::chrono::steady_clock::now();
  okvs::Galois128 delta_gf128(delta);
  std::vector<uint128_t> k(okvssize);
  yacl::parallel_for(0, okvssize, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      k[idx] = b[idx] ^ (delta_gf128 * aprime[idx]).get<uint128_t>(0);
    }
  });
  const auto t3 = std::chrono::steady_clock::now();
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  ourokvs.DecodeOtherP(elem_hashes, sendermasks, k);
  const auto t4 = std::chrono::steady_clock::now();
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] =
          sendermasks[idx] ^ (delta_gf128 * elem_hashes[idx]).get<uint128_t>(0);
    }
  });
  const auto t5 = std::chrono::steady_clock::now();
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Send masks of sender");
  const auto t6 = std::chrono::steady_clock::now();

  auto ms = [](auto start, auto end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
        .count();
  };
  std::cout << "[Send] VOLE: " << ms(t0, t1) << " ms" << std::endl;
  std::cout << "[Send] Recv A': " << ms(t1, t2) << " ms" << std::endl;
  std::cout << "[Send] Compute k: " << ms(t2, t3) << " ms" << std::endl;
  std::cout << "[Send] Decode masks: " << ms(t3, t4) << " ms" << std::endl;
  std::cout << "[Send] Delta mix: " << ms(t4, t5) << " ms" << std::endl;
  std::cout << "[Send] Send masks: " << ms(t5, t6) << " ms" << std::endl;
}
