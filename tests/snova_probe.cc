// Native probe for the SNOVA Python model tests.  It reads line commands from
// stdin and links the pinned round-2 reference through the PQCFuzz adapter; it
// never reimplements the target.
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "adapters/snova/sig_adapter.h"

#ifndef PQCFUZZ_SNOVA_IMPLEMENTATION_BASE
#define PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "snova_reference"
#endif

#ifndef PQCFUZZ_SNOVA_TEST_ID
#define PQCFUZZ_SNOVA_TEST_ID PQCFUZZ_SNOVA_IMPLEMENTATION_BASE "_esk"
#endif

#define PQCFUZZ_SNOVA_PROBE_ID PQCFUZZ_SNOVA_TEST_ID

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

const pqcfuzz_sig_adapter *Adapter() { return pqcfuzz_get_snova_sig_adapter(PQCFUZZ_SNOVA_PROBE_ID); }
const pqcfuzz_snova_api *Api() { return pqcfuzz_get_snova_api(PQCFUZZ_SNOVA_PROBE_ID); }

}  // namespace

int main() {
  const pqcfuzz_sig_adapter *adapter = Adapter();
  const pqcfuzz_snova_api *api = Api();
  if (adapter == nullptr || api == nullptr) {
    std::cout << "UNAVAILABLE\n";
    return 0;
  }
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) {
      continue;
    }
    std::istringstream stream(line);
    std::string command;
    stream >> command;
    if (command == "SIZES") {
      std::cout << "SIZES " << adapter->pk_len << " " << adapter->sk_len << " " << adapter->sig_max_len << " "
                << api->hash_bytes << " " << api->expanded_pk_len << " " << api->backend << " " << api->sk_format
                << "\n";
    } else if (command == "KEYGEN") {
      std::string seed_hex;
      stream >> seed_hex;
      std::vector<uint8_t> seed = FromHex(seed_hex);
      std::vector<uint8_t> pk(adapter->pk_len);
      std::vector<uint8_t> sk(adapter->sk_len);
      const pqcfuzz_status status = adapter->keygen_seeded(pk.data(), sk.data(), seed.data(), seed.size());
      std::cout << "KEYGEN " << static_cast<int>(status) << " " << ToHex(pk.data(), pk.size()) << " "
                << ToHex(sk.data(), sk.size()) << "\n";
    } else if (command == "SIGN") {
      std::string seed_hex;
      std::string message_hex;
      std::string salt_hex;
      stream >> seed_hex >> message_hex >> salt_hex;
      std::vector<uint8_t> seed = FromHex(seed_hex);
      std::vector<uint8_t> message = FromHex(message_hex);
      std::vector<uint8_t> salt = FromHex(salt_hex);
      std::vector<uint8_t> pk(adapter->pk_len);
      std::vector<uint8_t> sk(adapter->sk_len);
      adapter->keygen_seeded(pk.data(), sk.data(), seed.data(), seed.size());
      std::vector<uint8_t> sig(adapter->sig_max_len);
      size_t sig_len = sig.size();
      const pqcfuzz_status status = adapter->sign_seeded(sig.data(), &sig_len, message.data(), message.size(),
                                                         sk.data(), nullptr, 0, salt.data(), salt.size());
      if (status != PQCFUZZ_OK) {
        std::cout << "SIGN " << static_cast<int>(status) << " - -\n";
        continue;
      }
      std::cout << "SIGN " << static_cast<int>(status) << " " << ToHex(pk.data(), pk.size()) << " "
                << ToHex(sig.data(), sig_len) << "\n";
    } else if (command == "VERIFY") {
      std::string pk_hex;
      std::string message_hex;
      std::string sig_hex;
      stream >> pk_hex >> message_hex >> sig_hex;
      std::vector<uint8_t> pk = FromHex(pk_hex);
      std::vector<uint8_t> message = FromHex(message_hex);
      std::vector<uint8_t> sig = FromHex(sig_hex);
      const pqcfuzz_status status = adapter->verify(sig.data(), sig.size(), message.data(), message.size(), pk.data(),
                                                    nullptr, 0);
      std::cout << "VERIFY " << (status == PQCFUZZ_OK ? 1 : 0) << " " << static_cast<int>(status) << "\n";
    } else if (command == "VERIFYDIGEST") {
      std::string pk_hex;
      std::string digest_hex;
      std::string sig_hex;
      stream >> pk_hex >> digest_hex >> sig_hex;
      std::vector<uint8_t> pk = FromHex(pk_hex);
      std::vector<uint8_t> digest = FromHex(digest_hex);
      std::vector<uint8_t> sig = FromHex(sig_hex);
      const pqcfuzz_status status = api->verify_digest(sig.data(), sig.size(), digest.data(), digest.size(), pk.data());
      std::cout << "VERIFYDIGEST " << (status == PQCFUZZ_OK ? 1 : 0) << " " << static_cast<int>(status) << "\n";
    } else if (command == "EXPAND") {
      std::string pk_hex;
      stream >> pk_hex;
      std::vector<uint8_t> pk = FromHex(pk_hex);
      if (pk.size() != adapter->pk_len) {
        std::cout << "EXPAND -1 -\n";
        continue;
      }
      std::vector<uint8_t> expanded(api->expanded_pk_len);
      api->expand_public(expanded.data(), pk.data());
      std::cout << "EXPAND " << api->expanded_pk_len << " " << ToHex(expanded.data(), expanded.size()) << "\n";
    } else if (command == "KEYGENFROM") {
      std::string sk_hex;
      stream >> sk_hex;
      std::vector<uint8_t> sk = FromHex(sk_hex);
      std::vector<uint8_t> pk(adapter->pk_len);
      const pqcfuzz_status status = api->keygen_from_sk(pk.data(), sk.data(), sk.size());
      std::cout << "KEYGENFROM " << static_cast<int>(status) << " " << ToHex(pk.data(), pk.size()) << "\n";
    } else {
      std::cout << "UNKNOWN\n";
    }
  }
  return 0;
}
