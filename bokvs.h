// Copyright 2024 Guowei Ling.
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
#include <cstring>
#include "yacl/base/int128.h"
#include "examples/fastpsi/galois128.h"

struct Row {
    int64_t pos;
    int64_t bpos;
    std::vector<std::uint8_t> row;
    uint128_t value;
};

inline uint128_t BytesToUint128(std::vector<uint8_t> bytes) {
    uint128_t value = 0;
    for (int i = 0; i < 16; ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}



class OKVSBK {
public:
    OKVSBK(int64_t n, int64_t w, double e) 
        : n_(n), m_(std::ceil(n * e)), w_(w), r_(m_ - w), b_(w / 8), e_(e), p_(m_, 0) 
    {
    }

    int64_t getN() const {
        return n_;
    }

    int64_t getM() const {
        return m_;
    }

    int64_t getW() const {
        return w_;
    }

    int64_t getR() const {
        return r_;
    }

    double getE() const {
        return e_;
    }

     double getB() const {
        return b_;
    }

    bool Encode(std::vector<uint128_t> keys, std::vector<uint128_t> values);
    void Decode(std::vector<uint128_t> keys, std::vector<uint128_t>& values);
    void DecodeOtherP(std::vector<uint128_t> keys, std::vector<uint128_t>& values,std::vector<uint128_t> p) const;
    void Mul(okvs::Galois128 delta_gf128);

private:
    int64_t n_; // okvs存储的k-v长度
    int64_t m_; // okvs的实际长度
    int64_t w_; // 随机块的长度
    int64_t r_; // hashrange
    int64_t b_;
    double e_;
public:
    std::vector<uint128_t> p_;  // 存储m长度的向量，初始化为0
};

