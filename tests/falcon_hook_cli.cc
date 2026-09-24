// Test-only CLI over the Falcon reference hooks (src/adapters/falcon/falcon_test_hooks.h).
// Compiled by tests/falcon_model_test.py and tests/falcon_oracles_test.py with
// -DPQCFUZZ_HAVE_FALCON and the vendored reference sources.  It is never part
// of a production fuzzer or replay binary.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "adapters/falcon/falcon_test_hooks.h"
#include "adapters/falcon/signed_message_adapter.h"

#ifdef PQCFUZZ_HAVE_FALCON
#include "falcon.h"
extern "C" {
#include "katrng.h"
}
#endif

namespace {

int HexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::vector<uint8_t> ParseHex(const char *hex) {
  std::vector<uint8_t> out;
  if (hex == nullptr) return out;
  size_t len = std::strlen(hex);
  if (len % 2 != 0) return out;
  for (size_t i = 0; i < len; i += 2) {
    int hi = HexVal(hex[i]);
    int lo = HexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

void PrintHex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
}

unsigned ParseLogn(const char *value) {
  return static_cast<unsigned>(std::strtoul(value, nullptr, 10));
}

int ParseSigType(const char *value) {
  if (std::strcmp(value, "compressed") == 0) return 1;
  if (std::strcmp(value, "padded") == 0) return 2;
  if (std::strcmp(value, "ct") == 0) return 3;
  return std::atoi(value);
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: falcon_hook_cli <mode> [...]\n");
    return 2;
  }
  const std::string mode = argv[1];
  if (mode == "hash" && argc == 5) {
    const std::vector<uint8_t> salt = ParseHex(argv[2]);
    const std::vector<uint8_t> message = ParseHex(argv[3]);
    const unsigned logn = ParseLogn(argv[4]);
    std::vector<uint16_t> coefficients;
    if (!pqcfuzz::falcon_test::HookHashToPoint(salt.data(), salt.size(), message.data(), message.size(), logn,
                                               &coefficients)) {
      std::printf("ERR\n");
      return 1;
    }
    for (size_t i = 0; i < coefficients.size(); ++i) {
      std::printf("%04x%s", coefficients[i], i + 1 == coefficients.size() ? "" : ",");
    }
    std::printf("\n");
    return 0;
  }
  if (mode == "compdecode" && argc == 4) {
    const std::vector<uint8_t> payload = ParseHex(argv[2]);
    const unsigned logn = ParseLogn(argv[3]);
    std::vector<int16_t> coefficients;
    size_t consumed = 0;
    if (!pqcfuzz::falcon_test::HookCompDecode(payload.data(), payload.size(), logn, &coefficients, &consumed)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("consumed=%zu ", consumed);
    for (size_t i = 0; i < coefficients.size(); ++i) {
      std::printf("%d%s", coefficients[i], i + 1 == coefficients.size() ? "" : ",");
    }
    std::printf("\n");
    return 0;
  }
  if (mode == "compencode" && argc == 4) {
    const unsigned logn = ParseLogn(argv[2]);
    std::vector<int16_t> coefficients;
    const char *cursor = argv[3];
    while (*cursor != '\0') {
      char *end = nullptr;
      const long value = std::strtol(cursor, &end, 10);
      if (end == cursor) break;
      coefficients.push_back(static_cast<int16_t>(value));
      cursor = (*end == ',') ? end + 1 : end;
    }
    std::vector<uint8_t> payload;
    if (!pqcfuzz::falcon_test::HookCompEncode(coefficients, logn, &payload)) {
      std::printf("ERR\n");
      return 1;
    }
    PrintHex(payload.data(), payload.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "trimdecode" && argc == 4) {
    const std::vector<uint8_t> payload = ParseHex(argv[2]);
    const unsigned logn = ParseLogn(argv[3]);
    std::vector<int16_t> coefficients;
    if (!pqcfuzz::falcon_test::HookTrimDecode(payload.data(), payload.size(), logn, &coefficients)) {
      std::printf("ERR\n");
      return 1;
    }
    for (size_t i = 0; i < coefficients.size(); ++i) {
      std::printf("%d%s", coefficients[i], i + 1 == coefficients.size() ? "" : ",");
    }
    std::printf("\n");
    return 0;
  }
  if (mode == "keygen" && argc == 4) {
    const std::vector<uint8_t> seed = ParseHex(argv[2]);
    const unsigned logn = ParseLogn(argv[3]);
    if (seed.size() != 48) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    if (!pqcfuzz::falcon_test::HookKeygenFromSeed(seed.data(), logn, &pk, &sk)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("PK ");
    PrintHex(pk.data(), pk.size());
    std::printf("\nSK ");
    PrintHex(sk.data(), sk.size());
    std::printf("\n");
    std::vector<int8_t> f, g, F, G;
    if (pqcfuzz::falcon_test::HookCompletePrivate(sk.data(), logn, &f, &g, &F, &G)) {
      const auto print_ints = [](const char *label, const std::vector<int8_t> &values) {
        std::printf("%s ", label);
        for (size_t i = 0; i < values.size(); ++i) {
          std::printf("%d%s", values[i], i + 1 == values.size() ? "" : ",");
        }
        std::printf("\n");
      };
      print_ints("F", f);
      print_ints("G", g);
      print_ints("FBIG", F);
      print_ints("GBIG", G);
    }
    return 0;
  }
  if (mode == "sign" && argc == 7) {
    const std::vector<uint8_t> seed = ParseHex(argv[2]);
    const unsigned logn = ParseLogn(argv[3]);
    const int sig_type = ParseSigType(argv[4]);
    const std::vector<uint8_t> message = ParseHex(argv[5]);
    const std::vector<uint8_t> sk = ParseHex(argv[6]);
    if (seed.size() != 48 || sk.empty()) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<uint8_t> signature;
    if (!pqcfuzz::falcon_test::HookSignFromSeed(seed.data(), logn, sk.data(), message.data(), message.size(),
                                                sig_type, &signature)) {
      std::printf("ERR\n");
      return 1;
    }
    PrintHex(signature.data(), signature.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "verify" && argc == 6) {
    const int sig_type = ParseSigType(argv[2]);
    const std::vector<uint8_t> pk = ParseHex(argv[3]);
    const std::vector<uint8_t> message = ParseHex(argv[4]);
    const std::vector<uint8_t> signature = ParseHex(argv[5]);
    const bool accepted = pqcfuzz::falcon_test::HookVerify(signature.data(), signature.size(), message.data(),
                                                           message.size(), pk.data(), sig_type);
    std::printf("%s\n", accepted ? "ACCEPT" : "REJECT");
    return 0;
  }
  if (mode == "kat" && argc == 5) {
    const std::vector<uint8_t> seed = ParseHex(argv[2]);
    const std::vector<uint8_t> message = ParseHex(argv[3]);
    const unsigned logn = ParseLogn(argv[4]);
    if (seed.size() != 48) {
      std::printf("ERR\n");
      return 1;
    }
    randombytes_init(const_cast<unsigned char *>(seed.data()), nullptr, 256);
    unsigned char keygen_seed[48];
    randombytes(keygen_seed, 48);
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    if (!pqcfuzz::falcon_test::HookKeygenFromSeed(keygen_seed, logn, &pk, &sk)) {
      std::printf("ERR\n");
      return 1;
    }
    unsigned char nonce[40];
    randombytes(nonce, 40);
    shake256_context hash_data;
    shake256_init(&hash_data);
    shake256_inject(&hash_data, nonce, 40);
    shake256_inject(&hash_data, message.data(), message.size());
    unsigned char sampler_seed[48];
    randombytes(sampler_seed, 48);
    shake256_context rng;
    shake256_init(&rng);
    shake256_inject(&rng, sampler_seed, 48);
    shake256_flip(&rng);
    std::vector<uint8_t> detached(FALCON_SIG_COMPRESSED_MAXSIZE(logn));
    size_t detached_len = detached.size();
    std::vector<uint8_t> tmp(FALCON_TMPSIZE_SIGNDYN(logn));
    if (falcon_sign_dyn_finish(&rng, detached.data(), &detached_len, FALCON_SIG_COMPRESSED, sk.data(), sk.size(),
                               &hash_data, nonce, tmp.data(), tmp.size()) != 0) {
      std::printf("ERR\n");
      return 1;
    }
    detached.resize(detached_len);
    const size_t compressed_len = detached.size() - 41;
    const size_t sigpart_len = 1 + compressed_len;
    std::vector<uint8_t> signed_message(2 + 40 + message.size() + sigpart_len);
    signed_message[0] = static_cast<uint8_t>(sigpart_len >> 8);
    signed_message[1] = static_cast<uint8_t>(sigpart_len & 0xFF);
    std::memcpy(signed_message.data() + 2, detached.data() + 1, 40);
    std::memcpy(signed_message.data() + 42, message.data(), message.size());
    signed_message[42 + message.size()] = static_cast<uint8_t>(0x20 + logn);
    std::memcpy(signed_message.data() + 43 + message.size(), detached.data() + 41, compressed_len);
    std::printf("PK ");
    PrintHex(pk.data(), pk.size());
    std::printf("\nSK ");
    PrintHex(sk.data(), sk.size());
    std::printf("\nSM ");
    PrintHex(signed_message.data(), signed_message.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "open" && argc == 6) {
    const unsigned logn = ParseLogn(argv[2]);
    const std::vector<uint8_t> pk = ParseHex(argv[3]);
    const std::vector<uint8_t> sm = ParseHex(argv[4]);
    const size_t expected_mlen = static_cast<size_t>(std::strtoul(argv[5], nullptr, 10));
    std::vector<uint8_t> message(sm.size() + 64);
    size_t message_len = message.size();
    const pqcfuzz_status status = pqcfuzz::falcon_internal::OpenAttached(
        logn, message.data(), &message_len, sm.data(), sm.size(), pk.data());
    if (status != PQCFUZZ_OK || message_len != expected_mlen) {
      std::printf("ERR\n");
      return 1;
    }
    message.resize(message_len);
    PrintHex(message.data(), message.size());
    std::printf("\n");
    return 0;
  }
  std::fprintf(stderr, "unknown mode or bad arguments\n");
  return 2;
}
