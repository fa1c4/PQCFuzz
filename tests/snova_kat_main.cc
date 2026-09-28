// Official SNOVA KAT runner.  Reproduces one response record with the pinned
// NIST AES256-CTR DRBG (nistkat/rng.c): randombytes_init(seed) ->
// crypto_sign_keypair -> crypto_sign(message).  Input lines:
//   KAT <seed_hex> <message_hex>
// Output lines:
//   KAT <status> <pk_hex> <sk_hex> <smlen> <sm_hex>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "api.h"

extern "C" {
#include "nistkat/rng.h"
}

namespace {

std::vector<uint8_t> FromHex(const std::string &hex) {
  std::vector<uint8_t> out;
  if (hex.size() % 2 != 0) {
    return out;
  }
  for (size_t i = 0; i < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string ToHex(const uint8_t *data, size_t size) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(digits[(data[i] >> 4) & 0xF]);
    out.push_back(digits[data[i] & 0xF]);
  }
  return out;
}

}  // namespace

int main() {
  snova_init();
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) {
      continue;
    }
    std::istringstream stream(line);
    std::string command;
    stream >> command;
    if (command != "KAT") {
      std::cout << "UNKNOWN\n";
      continue;
    }
    std::string seed_hex;
    std::string message_hex;
    stream >> seed_hex >> message_hex;
    std::vector<uint8_t> seed = FromHex(seed_hex);
    std::vector<uint8_t> message = FromHex(message_hex);
    if (seed.size() != 48) {
      std::cout << "KAT -1 - - -\n";
      continue;
    }
    std::vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(CRYPTO_SECRETKEYBYTES);
    randombytes_init(seed.data(), nullptr, 256);
    if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
      std::cout << "KAT -2 - - - -\n";
      continue;
    }
    std::vector<uint8_t> sm(CRYPTO_BYTES + message.size());
    unsigned long long smlen = 0;
    if (crypto_sign(sm.data(), &smlen, message.data(), message.size(), sk.data()) != 0) {
      std::cout << "KAT -3 - - - -\n";
      continue;
    }
    std::cout << "KAT 0 " << ToHex(pk.data(), pk.size()) << " " << ToHex(sk.data(), sk.size()) << " " << smlen << " "
              << ToHex(sm.data(), static_cast<size_t>(smlen)) << "\n";
  }
  return 0;
}
