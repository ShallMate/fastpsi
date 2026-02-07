// Copyright 2026 Guowei Ling
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

#pragma once

#include <cmath>
#include <cstdint>
#include <vector>

#include "examples/fastpsi/galois128.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"

class OKVSBKV2 {
 public:
  OKVSBKV2(int64_t n, int64_t w, double e)
      : n_(n),
        m_(std::ceil(n * e)),
        w_(w),
        r_(m_ - w),
        band_length_(w),
        e_(e),
        p_(m_, 0) {
    YACL_ENFORCE(w_ <= kMaxBandBits,
                 "band length exceeds max capacity: w={}, max={}", w_,
                 kMaxBandBits);
  }

  int64_t getN() const { return n_; }
  int64_t getM() const { return m_; }
  int64_t getW() const { return w_; }
  int64_t getR() const { return r_; }
  double getE() const { return e_; }

  bool Encode(std::vector<uint128_t> keys, std::vector<uint128_t> values);
  void Decode(std::vector<uint128_t> keys, std::vector<uint128_t>& values);
  void DecodeOtherP(std::vector<uint128_t> keys, std::vector<uint128_t>& values,
                    const std::vector<uint128_t>& p) const;
  void DecodeDifflenP(std::vector<uint128_t> keys,
                      std::vector<uint128_t>& values,
                      const std::vector<uint128_t>& p) const;
  void Mul(okvs::Galois128 delta_gf128);

 private:
  static constexpr int64_t kMaxBandBits = 128 * 6;
  int64_t n_;  // okvs存储的k-v长度
  int64_t m_;  // okvs的实际长度
  int64_t w_;  // 随机块的长度 (band length)
  int64_t r_;  // hashrange
  int64_t band_length_;  // Band length (same as w_)
  double e_;

 public:
  std::vector<uint128_t> p_;  // 存储m长度的向量，初始化为0
};
