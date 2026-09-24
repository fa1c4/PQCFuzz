// Test-only CLI over the pinned NTRU reference (public NIST API plus the
// reference_adapter hooks).  It is compiled once per parameter set by
// tests/ntru_model_test.py and tests/ntru_oracles_test.py and is never part of
// a production binary.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "api.h"
#include "katrng.h"
#include "params.h"
}
#include "adapters/ntru/reference_adapter.h"

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
  const size_t len = std::strlen(hex);
  if (len % 2 != 0) return {};
  for (size_t i = 0; i < len; i += 2) {
    const int hi = HexVal(hex[i]);
    const int lo = HexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::vector<int> ParseInts(const char *csv) {
  std::vector<int> out;
  if (csv == nullptr) return out;
  const char *cursor = csv;
  while (*cursor != '\0') {
    char *end = nullptr;
    const long value = std::strtol(cursor, &end, 10);
    if (end == cursor) break;
    out.push_back(static_cast<int>(value));
    cursor = (*end == ',') ? end + 1 : end;
  }
  return out;
}

void PrintHex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
}

void PrintInts(const char *label, const std::vector<int> &values) {
  std::printf("%s=", label);
  for (size_t i = 0; i < values.size(); ++i) {
    std::printf("%d%s", values[i], i + 1 == values.size() ? "" : ",");
  }
  std::printf("\n");
}

int ModeKat(const char *seed_hex) {
  const std::vector<uint8_t> seed = ParseHex(seed_hex);
  if (seed.size() != 48) {
    std::printf("ERR\n");
    return 1;
  }
  randombytes_init(const_cast<unsigned char *>(seed.data()), nullptr, 256);
  std::vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES);
  std::vector<uint8_t> sk(CRYPTO_SECRETKEYBYTES);
  std::vector<uint8_t> ct(CRYPTO_CIPHERTEXTBYTES);
  std::vector<uint8_t> ss(CRYPTO_BYTES);
  std::vector<uint8_t> ss2(CRYPTO_BYTES);
  if (crypto_kem_keypair(pk.data(), sk.data()) != 0 || crypto_kem_enc(ct.data(), ss.data(), pk.data()) != 0 ||
      crypto_kem_dec(ss2.data(), ct.data(), sk.data()) != 0 || ss != ss2) {
    std::printf("ERR\n");
    return 1;
  }
  std::printf("pk=");
  PrintHex(pk.data(), pk.size());
  std::printf("\nsk=");
  PrintHex(sk.data(), sk.size());
  std::printf("\nct=");
  PrintHex(ct.data(), ct.size());
  std::printf("\nss=");
  PrintHex(ss.data(), ss.size());
  std::printf("\n");
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: ntru_hook_cli <mode> [...]\n");
    return 2;
  }
  const std::string mode = argv[1];
  if (mode == "kat" && argc == 3) {
    return ModeKat(argv[2]);
  }
  if (mode == "owcpa_keypair" && argc == 3) {
    const std::vector<uint8_t> seed = ParseHex(argv[2]);
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    if (!pqcfuzz::ntru_reference::SeedKeypair(seed.data(), seed.size(), &pk, &sk)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("pk=");
    PrintHex(pk.data(), pk.size());
    std::printf("\nsk=");
    PrintHex(sk.data(), sk.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "encaps" && argc == 4) {
    const std::vector<uint8_t> seed = ParseHex(argv[2]);
    const std::vector<uint8_t> pk = ParseHex(argv[3]);
    std::vector<uint8_t> ct;
    std::vector<uint8_t> ss;
    if (!pqcfuzz::ntru_reference::SeedEncaps(seed.data(), seed.size(), pk.data(), pk.size(), &ct, &ss)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("ct=");
    PrintHex(ct.data(), ct.size());
    std::printf("\nss=");
    PrintHex(ss.data(), ss.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "sample_rm" && argc == 3) {
    const std::vector<uint8_t> seed = ParseHex(argv[2]);
    std::vector<uint8_t> r;
    std::vector<uint8_t> m;
    if (!pqcfuzz::ntru_reference::SampleRm(seed.data(), seed.size(), &r, &m)) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<int> ri(r.begin(), r.end());
    std::vector<int> mi(m.begin(), m.end());
    PrintInts("r", ri);
    PrintInts("m", mi);
    return 0;
  }
  if (mode == "decrypt" && argc == 4) {
    const std::vector<uint8_t> sk = ParseHex(argv[2]);
    const std::vector<uint8_t> ct = ParseHex(argv[3]);
    std::vector<uint8_t> r;
    std::vector<uint8_t> m;
    bool fail = false;
    bool fail_padding = false;
    bool fail_m = false;
    bool fail_r = false;
    if (!pqcfuzz::ntru_reference::DpkeDecryptDetailed(ct.data(), ct.size(), sk.data(), sk.size(), &r, &m, &fail,
                                                      &fail_padding, &fail_m, &fail_r)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("fail=%d pad=%d m=%d r=%d\n", fail ? 1 : 0, fail_padding ? 1 : 0, fail_m ? 1 : 0, fail_r ? 1 : 0);
    std::vector<int> ri(r.begin(), r.end());
    std::vector<int> mi(m.begin(), m.end());
    PrintInts("rtrits", ri);
    PrintInts("mtrits", mi);
    return 0;
  }
  if (mode == "decaps" && argc == 4) {
    const std::vector<uint8_t> sk = ParseHex(argv[2]);
    const std::vector<uint8_t> ct = ParseHex(argv[3]);
    if (sk.size() != CRYPTO_SECRETKEYBYTES || ct.size() != CRYPTO_CIPHERTEXTBYTES) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<uint8_t> ss(CRYPTO_BYTES);
    const int rc = crypto_kem_dec(ss.data(), ct.data(), sk.data());
    std::printf("rc=%d\nss=", rc);
    PrintHex(ss.data(), ss.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "pack3" && argc == 3) {
    const std::vector<int> values = ParseInts(argv[2]);
    std::vector<uint8_t> trits(values.begin(), values.end());
    std::vector<uint8_t> payload;
    if (!pqcfuzz::ntru_reference::Pack3(trits, &payload)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("payload=");
    PrintHex(payload.data(), payload.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "unpack3" && argc == 3) {
    const std::vector<uint8_t> payload = ParseHex(argv[2]);
    std::vector<uint8_t> trits;
    if (!pqcfuzz::ntru_reference::Unpack3(payload.data(), payload.size(), &trits)) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<int> values(trits.begin(), trits.end());
    PrintInts("trits", values);
    return 0;
  }
  if (mode == "packq" && argc == 3) {
    const std::vector<int> values = ParseInts(argv[2]);
    std::vector<uint16_t> coefficients(values.begin(), values.end());
    std::vector<uint8_t> payload;
    if (!pqcfuzz::ntru_reference::PackQ(coefficients, &payload)) {
      std::printf("ERR\n");
      return 1;
    }
    std::printf("payload=");
    PrintHex(payload.data(), payload.size());
    std::printf("\n");
    return 0;
  }
  if (mode == "unpackq" && argc == 3) {
    const std::vector<uint8_t> payload = ParseHex(argv[2]);
    std::vector<uint16_t> coefficients;
    if (!pqcfuzz::ntru_reference::UnpackQ(payload.data(), payload.size(), &coefficients)) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<int> values(coefficients.begin(), coefficients.end());
    PrintInts("coeffs", values);
    return 0;
  }
  if (mode == "lift" && argc == 3) {
    const std::vector<int> values = ParseInts(argv[2]);
    std::vector<uint8_t> trits(values.begin(), values.end());
    std::vector<uint16_t> coefficients;
    if (!pqcfuzz::ntru_reference::Lift(trits, &coefficients)) {
      std::printf("ERR\n");
      return 1;
    }
    std::vector<int> out(coefficients.begin(), coefficients.end());
    PrintInts("coeffs", out);
    return 0;
  }
  if (mode == "variant") {
    std::printf("%s\n", pqcfuzz::ntru_reference::IsHps() ? "HPS" : "HRSS");
    return 0;
  }
  std::fprintf(stderr, "unknown mode or bad arguments\n");
  return 2;
}
