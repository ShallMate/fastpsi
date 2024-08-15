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

#include <iostream>
#include <ostream>
#include <vector>

#include "examples/fastpsi/bokvs.h"

#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"
#include "examples/fastpsi/fastpsi.h"


int main() {
  size_t n = 1<<20;
  size_t w = 512;
  double e = 1.01;
  OKVSBK ourokvs(n, w, e);
  auto r = ourokvs.getR();
  std::cout << "N: " << ourokvs.getN() << std::endl;
  std::cout << "M: " << ourokvs.getM() << std::endl;
  std::cout << "W: " << ourokvs.getW() << std::endl;
  std::cout << "R: " << r << std::endl;
  std::cout << "e: " << ourokvs.getE() << std::endl;

  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  size_t elementstart = 10;
  size_t intersize = n-elementstart;
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(elementstart, n);
  
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  std::future<void> fastpsi_sender = std::async(
      std::launch::async, [&] { FastPsiSend(lctxs[0], items_a, ourokvs); });

  std::future<std::vector<uint128_t>> fastpsi_receiver =
      std::async(std::launch::async,
                 [&] { return FastPsiRecv(lctxs[1], items_b, ourokvs); });

  fastpsi_sender.get();
  auto psi_result = fastpsi_receiver.get();
  if(psi_result.size() == intersize){
    std::cout<<"The PSI protocol has been successfully executed"<<std::endl;
  }
  std::sort(psi_result.begin(), psi_result.end());
  std::cout<<"The intersection size is "<<psi_result.size()<<std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load())+bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
}
