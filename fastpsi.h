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
#pragma once

#include <vector>

#include "examples/fastpsi/bokvsv2.h"
#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"

std::vector<uint128_t> FastPsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, OKVSBKV2& ourokvs);

void FastPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& elem_hashes,
                 const OKVSBKV2& ourokvs);

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size);