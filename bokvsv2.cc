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

#include "examples/fastpsi/bokvsv2.h"

#include <immintrin.h>
#include <omp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <vector>

#define OC_ENALBE_AESNI
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/AES.h"

#include "examples/fastpsi/uint.h"
#include "yacl/base/int128.h"
#include "yacl/utils/parallel.h"

// Use boost spreadsort for faster integer sorting
#include <boost/sort/spreadsort/spreadsort.hpp>

// SIMD optimization helpers
#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__AVX512DQ__)
#define USE_AVX512
#elif defined(__AVX2__)
#define USE_AVX2
#endif

// Mask table for AVX-512 optimization (similar to bandokvs)
#ifdef USE_AVX512
inline static constexpr __mmask8 mask_table[16] = {
    0, 3, 12, 15, 48, 51, 60, 63, 192, 195, 204, 207, 240, 243, 252, 255};
#endif

namespace {

inline oc::block ToOcBlock(uint128_t key) {
  uint64_t lo = static_cast<uint64_t>(key);
  uint64_t hi = static_cast<uint64_t>(key >> 64);
  return _mm_set_epi64x(static_cast<int64_t>(hi),
                        static_cast<int64_t>(lo));
}

// Optimized: Generate band word directly using oc::AES like bandokvs
template <typename BandWordT>
inline void GenerateBandWord(uint128_t key, int64_t r, int64_t band_length,
                             BandWordT& out_word, int64_t& band_start) {
  const int num_blocks = (band_length + 127) / 128;
  const __uint128_t high_mask =
      band_length % 128 == 0
          ? static_cast<__uint128_t>(-1)
          : (static_cast<__uint128_t>(1) << (band_length % 128)) - 1;
  const uint32_t divisor = static_cast<uint32_t>(r - band_length + 1);

  static thread_local oc::AES aes(oc::ZeroBlock);
  oc::block block = aes.hashBlock(ToOcBlock(key));
  uint32_t p = block.get<uint32_t>(0);
  band_start = static_cast<int64_t>(p % divisor);

  std::vector<oc::block> expanded_keys(static_cast<size_t>(num_blocks));
  std::vector<oc::block> blocks(static_cast<size_t>(num_blocks));
  for (int i = 0; i < num_blocks; ++i) {
    expanded_keys[static_cast<size_t>(i)] = block ^ oc::block(i);
  }
  aes.hashBlocks(expanded_keys, blocks);
  out_word.set(blocks.data(), num_blocks, high_mask);
}

template <typename BandWordT, typename BandAndValueT>
inline void GenerateBandAndValueDirect(uint128_t key, uint128_t value,
                                       int64_t r, int64_t band_length,
                                       BandAndValueT& out) {
  GenerateBandWord(key, r, band_length, out.band_, out.band_start_);
  out.value_ = value;
}

// Band structure: compact representation of a fixed-length bit vector
template <typename BandWordT>
struct BandT {
  int64_t band_start_;  // Starting position in OKVS
  BandWordT band_;
  int64_t idx_;  // Original index

  BandT() : band_start_(0), idx_(0) {}
  BandT(int64_t start, const BandWordT& band, int64_t idx)
      : band_start_(start), band_(band), idx_(idx) {}

  int64_t BandStart() const { return band_start_; }
  const BandWordT& RawBand() const { return band_; }
  int64_t Index() const { return idx_; }
};

// Band with associated value
template <typename BandWordT>
struct BandAndValueT {
  int64_t band_start_;
  uint128_t value_;
  BandWordT band_;

  BandAndValueT() : band_start_(0), value_(0) {}

  int64_t BandStart() const { return band_start_; }
  const BandWordT& RawBand() const { return band_; }
  uint128_t RawValue() const { return value_; }
  uint128_t& RawValue() { return value_; }
};

// Helper for sorting bands by band_start
template <typename BandAndValueT>
struct BandLessThan {
  bool operator()(const BandAndValueT& a, const BandAndValueT& b) const {
    return a.BandStart() < b.BandStart();
  }
};

template <typename BandAndValueT>
struct BandRightShift {
  int operator()(const BandAndValueT& x, unsigned int offset) const {
    return static_cast<int>(x.BandStart() >> offset);
  }
};

template <typename BandWordT>
using CompactBandT = BandWordT;

// Reduce to row echelon form using band structure (optimized version)
template <typename BandWordT, typename BandAndValueT>
bool ReduceToRowEchelon(const BandAndValueT* bands, int64_t n,
                        CompactBandT<BandWordT>* reduced_matrix,
                        uint128_t* reduced_values, int64_t m) {
  const CompactBandT<BandWordT> kZero = CompactBandT<BandWordT>(0);

  for (int64_t i = 0; i < n; ++i) {
    int64_t offset = bands[i].BandStart();
    CompactBandT<BandWordT> raw_band = bands[i].RawBand();
    uint128_t value = bands[i].RawValue();

    while (offset < m && reduced_matrix[offset] != kZero) {
      raw_band ^= reduced_matrix[offset];
      value ^= reduced_values[offset];

      while (offset < m && (raw_band & 1) == 0) {
        raw_band >>= 1;
        ++offset;
      }

      if (offset >= m) {
        break;
      }
    }

    if (raw_band == kZero) {
      continue;
    }

    if (offset < m) {
      reduced_matrix[offset] = raw_band;
      reduced_values[offset] = value;
    }
  }

  return true;
}

// AVX-512 optimized XOR based on band pattern (exactly like bandokvs DoXor)
// Use loop unrolling and direct byte extraction
#ifdef USE_AVX512
template <typename BandWordT>
__m512i DoXorBand(int64_t start_pos, const CompactBandT<BandWordT>& band,
                  const uint128_t* reduced_values, int64_t band_length) {
  __m512i res = _mm512_setzero_si512();

  const CompactBandT<BandWordT> kZero = CompactBandT<BandWordT>(0);
  if (band == kZero) {
    return res;
  }

  // Extract bytes directly from band (like bandokvs: *((uint8_t*)(&raw_band) + k))
  const uint8_t* band_bytes = reinterpret_cast<const uint8_t*>(&band);
  int64_t num_bytes = (band_length + 7) / 8;

  // Loop unrolling like bandokvs
  int64_t j = 0;
  int64_t k = 0;
  for (; j + 8 <= band_length && k < num_bytes; j += 8, k++) {
    uint8_t raw_band_mask = band_bytes[k];

    // Process lower 4 bits (first 4 positions)
    __mmask8 mask = mask_table[raw_band_mask & 0b1111];
    res = _mm512_xor_epi64(
        res, _mm512_maskz_loadu_epi64(mask, &reduced_values[start_pos + j]));

    // Process upper 4 bits (next 4 positions)
    __mmask8 mask2 = mask_table[(raw_band_mask >> 4) & 0b1111];
    res = _mm512_xor_epi64(
        res, _mm512_maskz_loadu_epi64(mask2,
                                      &reduced_values[start_pos + j + 4]));
  }

  // Handle remaining positions (if any)
  for (; j < band_length && k < num_bytes; j += 8, k++) {
    uint8_t raw_band_mask = band_bytes[k];
    int64_t remaining = std::min(static_cast<int64_t>(8), band_length - j);

    if (remaining > 0) {
      // Process lower 4 bits
      if (remaining >= 4) {
        __mmask8 mask = mask_table[raw_band_mask & 0b1111];
        res = _mm512_xor_epi64(
            res, _mm512_maskz_loadu_epi64(mask,
                                          &reduced_values[start_pos + j]));
      }

      // Process upper 4 bits
      if (remaining >= 8) {
        __mmask8 mask2 = mask_table[(raw_band_mask >> 4) & 0b1111];
        res = _mm512_xor_epi64(
            res, _mm512_maskz_loadu_epi64(mask2,
                                          &reduced_values[start_pos + j + 4]));
      }
    }
  }

  return res;
}

// Reduce 512-bit register to 128-bit result (similar to bandokvs DoXor512)
__m128i DoXor512(__m512i n) {
  __m128i a = _mm512_extracti64x2_epi64(n, 0);
  __m128i b = _mm512_extracti64x2_epi64(n, 1);
  __m128i c = _mm512_extracti64x2_epi64(n, 2);
  __m128i d = _mm512_extracti64x2_epi64(n, 3);
  __m128i ab = _mm_xor_si128(a, b);
  __m128i cd = _mm_xor_si128(c, d);
  __m128i res = _mm_xor_si128(ab, cd);
  return res;
}
#endif

// Solve the system (similar to bandokvs Solve)
template <typename BandWordT>
void Solve(const CompactBandT<BandWordT>* reduced_matrix,
           uint128_t* reduced_values, int64_t m, int64_t band_length) {
  const CompactBandT<BandWordT> kZero = CompactBandT<BandWordT>(0);
  for (int64_t i = m - 1; i >= 0; --i) {
    if (reduced_matrix[i] == kZero) {
      continue;
    }

#ifdef USE_AVX512
    // Use CompactBand directly, no vector conversion needed
    __m512i res =
        DoXorBand(i, reduced_matrix[i], reduced_values, band_length);
    __m128i res2 = DoXor512(res);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&reduced_values[i]), res2);
#else
    // Fallback: scalar XOR
    uint128_t res = 0;
    const auto& band = reduced_matrix[i];
    for (int64_t j = 0; j < band_length; j++) {
      if (band.GetBit(static_cast<int>(j))) {
        res ^= reduced_values[i + j];
      }
    }
    reduced_values[i] = res;
#endif
  }
}

template <typename BandWordT>
bool EncodeImpl(const std::vector<uint128_t>& keys,
                const std::vector<uint128_t>& values, int64_t n, int64_t m,
                int64_t r, int64_t band_length,
                std::vector<uint128_t>& p_out) {
  p_out.resize(m);
  std::fill(p_out.begin(), p_out.end(), static_cast<uint128_t>(0));

  using BandAndValue = BandAndValueT<BandWordT>;
  using CompactBand = CompactBandT<BandWordT>;
  auto* bands =
      static_cast<BandAndValue*>(std::malloc(n * sizeof(BandAndValue)));
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t i = begin; i < end; ++i) {
      GenerateBandAndValueDirect<BandWordT, BandAndValue>(
          keys[i], values[i], r, band_length, bands[i]);
    }
  });

  boost::sort::spreadsort::integer_sort(bands, bands + n,
                                        BandRightShift<BandAndValue>(),
                                        BandLessThan<BandAndValue>());

  std::vector<CompactBand> reduced_matrix(m);
  std::vector<uint128_t> reduced_values(m, 0);
  if (!ReduceToRowEchelon<BandWordT>(bands, n, reduced_matrix.data(),
                                     reduced_values.data(), m)) {
    std::free(bands);
    return false;
  }

  Solve<BandWordT>(reduced_matrix.data(), reduced_values.data(), m,
                   band_length);

  for (int64_t i = 0; i < m; i++) {
    p_out[i] = reduced_values[i];
  }

  std::free(bands);
  return true;
}

template <typename BandWordT>
void DecodeImpl(const std::vector<uint128_t>& keys,
                const std::vector<uint128_t>& p,
                std::vector<uint128_t>& values, int64_t n, int64_t r,
                int64_t band_length) {
  yacl::parallel_for(0, n, 4096, [&](int64_t begin, int64_t end) {
    for (int64_t i = begin; i < end; ++i) {
      BandWordT band;
      int64_t band_start = 0;
      GenerateBandWord(keys[i], r, band_length, band, band_start);

      uint128_t res = 0;
#ifdef USE_AVX512
      __m512i acc =
          DoXorBand(band_start, band, p.data(), band_length);
      __m128i acc128 = DoXor512(acc);
      _mm_storeu_si128(reinterpret_cast<__m128i*>(&res), acc128);
#else
      for (int64_t j = 0; j < band_length; j++) {
        if (band.GetBit(static_cast<int>(j))) {
          res ^= p[band_start + j];
        }
      }
#endif

      values[i] = res;
    }
  });
}

}  // namespace

bool OKVSBKV2::Encode(std::vector<uint128_t> keys,
                      std::vector<uint128_t> values) {
  const int num_blocks = static_cast<int>((band_length_ + 127) / 128);
  switch (num_blocks) {
    case 1:
      return EncodeImpl<band_okvs::uint<1>>(keys, values, n_, m_, r_,
                                            band_length_, p_);
    case 2:
      return EncodeImpl<band_okvs::uint<2>>(keys, values, n_, m_, r_,
                                            band_length_, p_);
    case 3:
      return EncodeImpl<band_okvs::uint<3>>(keys, values, n_, m_, r_,
                                            band_length_, p_);
    case 4:
      return EncodeImpl<band_okvs::uint<4>>(keys, values, n_, m_, r_,
                                            band_length_, p_);
    case 5:
      return EncodeImpl<band_okvs::uint<5>>(keys, values, n_, m_, r_,
                                            band_length_, p_);
    case 6:
      return EncodeImpl<band_okvs::uint<6>>(keys, values, n_, m_, r_,
                                            band_length_, p_);
    default:
      return false;
  }
}

void OKVSBKV2::Decode(std::vector<uint128_t> keys,
                      std::vector<uint128_t>& values) {
  const int num_blocks = static_cast<int>((band_length_ + 127) / 128);
  switch (num_blocks) {
    case 1:
      return DecodeImpl<band_okvs::uint<1>>(keys, p_, values, n_, r_,
                                            band_length_);
    case 2:
      return DecodeImpl<band_okvs::uint<2>>(keys, p_, values, n_, r_,
                                            band_length_);
    case 3:
      return DecodeImpl<band_okvs::uint<3>>(keys, p_, values, n_, r_,
                                            band_length_);
    case 4:
      return DecodeImpl<band_okvs::uint<4>>(keys, p_, values, n_, r_,
                                            band_length_);
    case 5:
      return DecodeImpl<band_okvs::uint<5>>(keys, p_, values, n_, r_,
                                            band_length_);
    case 6:
      return DecodeImpl<band_okvs::uint<6>>(keys, p_, values, n_, r_,
                                            band_length_);
    default:
      return;
  }
}

void OKVSBKV2::DecodeOtherP(std::vector<uint128_t> keys,
                            std::vector<uint128_t>& values,
                            const std::vector<uint128_t>& p) const {
  const int num_blocks = static_cast<int>((band_length_ + 127) / 128);
  switch (num_blocks) {
    case 1:
      return DecodeImpl<band_okvs::uint<1>>(keys, p, values, n_, r_,
                                            band_length_);
    case 2:
      return DecodeImpl<band_okvs::uint<2>>(keys, p, values, n_, r_,
                                            band_length_);
    case 3:
      return DecodeImpl<band_okvs::uint<3>>(keys, p, values, n_, r_,
                                            band_length_);
    case 4:
      return DecodeImpl<band_okvs::uint<4>>(keys, p, values, n_, r_,
                                            band_length_);
    case 5:
      return DecodeImpl<band_okvs::uint<5>>(keys, p, values, n_, r_,
                                            band_length_);
    case 6:
      return DecodeImpl<band_okvs::uint<6>>(keys, p, values, n_, r_,
                                            band_length_);
    default:
      return;
  }
}

void OKVSBKV2::DecodeDifflenP(std::vector<uint128_t> keys,
                              std::vector<uint128_t>& values,
                              const std::vector<uint128_t>& p) const {
  DecodeOtherP(keys, values, p);
}

void OKVSBKV2::Mul(okvs::Galois128 delta_gf128) {
  yacl::parallel_for(0, static_cast<int64_t>(p_.size()),
                     [&](int64_t begin, int64_t end) {
    for (int64_t i = begin; i < end; ++i) {
      p_[i] = (delta_gf128 * okvs::Galois128(p_[i])).get<uint128_t>(0);
    }
  });
}
