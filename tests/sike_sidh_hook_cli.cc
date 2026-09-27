// Test-only hook CLI for the pinned SIKE/SIDH reference.
//
// Commands:
//   kat <seed48_hex>              KEM KAT with the NIST AES256-CTR-DRBG
//   derive <coins96_hex>          deterministic KEM keypair+encaps
//   gate <sk_hex> <ct_hex>        independent re-encryption gate + H inputs
//   isogen2 <scalar_hex>          2-isogeny public key
//   isogen3 <scalar_hex>          3-isogeny public key
//   sidh <scalarA_hex> <scalarB_hex>  role public keys and shared values
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "adapters/rng_control.h"
#include "adapters/sike/reference_adapter.h"
#include "mutators/sha3.h"

#ifndef SIKE_API_HEADER
#define SIKE_API_HEADER "P434_api.h"
#endif
extern "C" {
#include SIKE_API_HEADER
}
extern "C" {
#include "katrng.h"
}
// katrng.c is compiled with -Drandombytes=kat_randombytes and
// -Drandombytes_init=kat_randombytes_init so the CLI can own `randombytes`.
extern "C" int kat_randombytes(unsigned char *out, unsigned long long out_len);
extern "C" int kat_randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string,
                                    int security_strength);

#ifndef SIKE_KEYPAIR
#define SIKE_KEYPAIR crypto_kem_keypair
#endif
#ifndef SIKE_ENC
#define SIKE_ENC crypto_kem_enc
#endif
#ifndef SIKE_DEC
#define SIKE_DEC crypto_kem_dec
#endif
#ifndef SIKE_E2_BITS
#define SIKE_E2_BITS 216
#endif
#ifndef SECRETKEY_B_BYTES
#define SECRETKEY_B_BYTES 28
#endif
#ifndef MSG_BYTES
#define MSG_BYTES 16
#endif
#ifndef SIDH_KEYGEN_A
#define SIDH_KEYGEN_A EphemeralKeyGeneration_A
#endif
#ifndef SIDH_KEYGEN_B
#define SIDH_KEYGEN_B EphemeralKeyGeneration_B
#endif
#ifndef SIDH_DERIVE_A
#define SIDH_DERIVE_A EphemeralSecretAgreement_A
#endif
#ifndef SIDH_DERIVE_B
#define SIDH_DERIVE_B EphemeralSecretAgreement_B
#endif

namespace {

std::string HexOf(const std::vector<uint8_t> &bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0Fu]);
  }
  return out;
}

bool FromHex(const std::string &hex, std::vector<uint8_t> *out) {
  if (out == nullptr || hex.size() % 2 != 0) {
    return false;
  }
  out->resize(hex.size() / 2);
  for (size_t i = 0; i < out->size(); ++i) {
    unsigned int byte = 0;
    if (std::sscanf(hex.c_str() + 2 * i, "%2x", &byte) != 1) {
      return false;
    }
    (*out)[i] = static_cast<uint8_t>(byte);
  }
  return true;
}

uint8_t ByteMaskForBits(size_t bits) {
  const size_t remainder = bits % 8;
  return remainder == 0 ? 0xFF : static_cast<uint8_t>((1u << remainder) - 1u);
}

int CommandKat(const std::vector<std::string> &args) {
  if (args.size() != 3) {
    return 2;
  }
  std::vector<uint8_t> seed;
  if (!FromHex(args[2], &seed) || seed.size() != 48) {
    return 3;
  }
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  unsigned char ss[CRYPTO_BYTES];
  unsigned char ss2[CRYPTO_BYTES];
  kat_randombytes_init(seed.data(), nullptr, 256);
  if (SIKE_KEYPAIR(pk, sk) != 0 || SIKE_ENC(ct, ss, pk) != 0 || SIKE_DEC(ss2, ct, sk) != 0) {
    return 4;
  }
  printf("pk=%s\n", HexOf(std::vector<uint8_t>(pk, pk + sizeof(pk))).c_str());
  printf("sk=%s\n", HexOf(std::vector<uint8_t>(sk, sk + sizeof(sk))).c_str());
  printf("ct=%s\n", HexOf(std::vector<uint8_t>(ct, ct + sizeof(ct))).c_str());
  printf("ss=%s\n", HexOf(std::vector<uint8_t>(ss, ss + sizeof(ss))).c_str());
  return 0;
}

int CommandDerive(const std::vector<std::string> &args) {
  if (args.size() != 3) {
    return 2;
  }
  std::vector<uint8_t> coins;
  if (!FromHex(args[2], &coins) || coins.empty()) {
    return 3;
  }
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  unsigned char ss[CRYPTO_BYTES];
  {
    pqcfuzz::ScopedRngOverride tape({coins.data(), coins.size(), true});
    if (SIKE_KEYPAIR(pk, sk) != 0) {
      return 4;
    }
  }
  {
    pqcfuzz::ScopedRngOverride tape({coins.data(), coins.size(), true});
    if (SIKE_ENC(ct, ss, pk) != 0) {
      return 5;
    }
  }
  printf("pk=%s\n", HexOf(std::vector<uint8_t>(pk, pk + sizeof(pk))).c_str());
  printf("sk=%s\n", HexOf(std::vector<uint8_t>(sk, sk + sizeof(sk))).c_str());
  printf("ct=%s\n", HexOf(std::vector<uint8_t>(ct, ct + sizeof(ct))).c_str());
  printf("ss=%s\n", HexOf(std::vector<uint8_t>(ss, ss + sizeof(ss))).c_str());
  return 0;
}

int CommandGate(const std::vector<std::string> &args) {
  if (args.size() != 4) {
    return 2;
  }
  std::vector<uint8_t> sk;
  std::vector<uint8_t> ct;
  if (!FromHex(args[2], &sk) || !FromHex(args[3], &ct)) {
    return 3;
  }
  if (sk.size() != CRYPTO_SECRETKEYBYTES || ct.size() != CRYPTO_CIPHERTEXTBYTES) {
    return 3;
  }
  const pqcfuzz::sike_reference::SikeReferenceHooks *hooks = pqcfuzz::sike_reference::GetSikeReferenceHooks();
  if (hooks == nullptr) {
    printf("hooks=missing\n");
    return 4;
  }
  const size_t msg_bytes = MSG_BYTES;
  const size_t nsk3 = SECRETKEY_B_BYTES;
  const size_t nsk2 = SIDH_SECRETKEYBYTES_A;
  const size_t np = (CRYPTO_PUBLICKEYBYTES / 6);
  const size_t pk_len = CRYPTO_PUBLICKEYBYTES;
  std::vector<uint8_t> s(sk.begin(), sk.begin() + static_cast<long>(msg_bytes));
  std::vector<uint8_t> sk3(sk.begin() + static_cast<long>(msg_bytes),
                           sk.begin() + static_cast<long>(msg_bytes + nsk3));
  std::vector<uint8_t> pk3(sk.begin() + static_cast<long>(msg_bytes + nsk3),
                           sk.begin() + static_cast<long>(msg_bytes + nsk3 + pk_len));
  std::vector<uint8_t> c0(ct.begin(), ct.begin() + static_cast<long>(pk_len));
  std::vector<uint8_t> c1(ct.begin() + static_cast<long>(pk_len), ct.end());
  std::vector<uint8_t> j(2 * np, 0);
  if (hooks->pke_j_invariant(j.data(), j.size(), sk3.data(), sk3.size(), c0.data(), c0.size()) != PQCFUZZ_OK) {
    return 5;
  }
  const std::vector<uint8_t> h = pqcfuzz::Shake256(j, msg_bytes);
  std::vector<uint8_t> m(msg_bytes, 0);
  for (size_t i = 0; i < msg_bytes; ++i) {
    m[i] = static_cast<uint8_t>(c1[i] ^ h[i]);
  }
  std::vector<uint8_t> g_input = m;
  g_input.insert(g_input.end(), pk3.begin(), pk3.end());
  std::vector<uint8_t> scalar = pqcfuzz::Shake256(g_input, nsk2);
  // e2 may not be a multiple of eight; the mask is (1 << (e2 % 8)) - 1.
  scalar[nsk2 - 1] &= ByteMaskForBits(SIKE_E2_BITS);
  std::vector<uint8_t> c0_prime(pk_len, 0);
  if (hooks->isogen2(c0_prime.data(), c0_prime.size(), scalar.data(), scalar.size()) != PQCFUZZ_OK) {
    return 6;
  }
  const bool gate = c0_prime == c0;
  std::vector<uint8_t> h_input = gate ? m : s;
  h_input.insert(h_input.end(), ct.begin(), ct.end());
  const std::vector<uint8_t> expected = pqcfuzz::Shake256(h_input, CRYPTO_BYTES);
  printf("gate=%s\n", gate ? "valid" : "fallback");
  printf("m=%s\n", HexOf(m).c_str());
  printf("r=%s\n", HexOf(scalar).c_str());
  printf("c0_prime=%s\n", HexOf(c0_prime).c_str());
  printf("expected=%s\n", HexOf(expected).c_str());
  return 0;
}

int CommandIsogen(const std::vector<std::string> &args, bool alice) {
  if (args.size() != 3) {
    return 2;
  }
  std::vector<uint8_t> scalar;
  if (!FromHex(args[2], &scalar)) {
    return 3;
  }
  std::vector<uint8_t> pk(SIDH_PUBLICKEYBYTES, 0);
  const int rc = alice ? SIDH_KEYGEN_A(scalar.data(), pk.data()) : SIDH_KEYGEN_B(scalar.data(), pk.data());
  if (rc != 0) {
    return 4;
  }
  printf("pk=%s\n", HexOf(pk).c_str());
  return 0;
}

int CommandSidh(const std::vector<std::string> &args) {
  if (args.size() != 4) {
    return 2;
  }
  std::vector<uint8_t> scalar_a;
  std::vector<uint8_t> scalar_b;
  if (!FromHex(args[2], &scalar_a) || !FromHex(args[3], &scalar_b)) {
    return 3;
  }
  std::vector<uint8_t> pk_a(SIDH_PUBLICKEYBYTES, 0);
  std::vector<uint8_t> pk_b(SIDH_PUBLICKEYBYTES, 0);
  std::vector<uint8_t> shared_a(SIDH_BYTES, 0);
  std::vector<uint8_t> shared_b(SIDH_BYTES, 0);
  if (SIDH_KEYGEN_A(scalar_a.data(), pk_a.data()) != 0 || SIDH_KEYGEN_B(scalar_b.data(), pk_b.data()) != 0) {
    return 4;
  }
  if (SIDH_DERIVE_A(scalar_a.data(), pk_b.data(), shared_a.data()) != 0 ||
      SIDH_DERIVE_B(scalar_b.data(), pk_a.data(), shared_b.data()) != 0) {
    return 5;
  }
  printf("pk_a=%s\n", HexOf(pk_a).c_str());
  printf("pk_b=%s\n", HexOf(pk_b).c_str());
  printf("shared_a=%s\n", HexOf(shared_a).c_str());
  printf("shared_b=%s\n", HexOf(shared_b).c_str());
  return 0;
}

}  // namespace

// The hook CLI drives one `randombytes` that prefers the harness RNG tape and
// otherwise falls back to the NIST AES256-CTR-DRBG (compiled with its symbols
// renamed to kat_*).
extern "C" int randombytes(unsigned char *out, unsigned long long out_len) {
  if (pqcfuzz_rng_fill_bytes(out, static_cast<size_t>(out_len))) {
    return 0;
  }
  return kat_randombytes(out, out_len);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    return 2;
  }
  std::vector<std::string> args(argv, argv + argc);
  if (args[1] == "kat") {
    return CommandKat(args);
  }
  if (args[1] == "derive") {
    return CommandDerive(args);
  }
  if (args[1] == "gate") {
    return CommandGate(args);
  }
  if (args[1] == "isogen2") {
    return CommandIsogen(args, true);
  }
  if (args[1] == "isogen3") {
    return CommandIsogen(args, false);
  }
  if (args[1] == "sidh") {
    return CommandSidh(args);
  }
  return 2;
}
