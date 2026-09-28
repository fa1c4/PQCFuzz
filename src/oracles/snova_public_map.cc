#include "oracles/snova_public_map.h"

#include <algorithm>
#include <cstring>

#include "mutators/sha3.h"

namespace pqcfuzz {
namespace {

// GF16 multiplication modulo x^4 + x + 1 (not integer multiplication mod 16).
uint8_t Gf16Mul(uint8_t a, uint8_t b) {
  uint8_t result = 0;
  uint8_t left = static_cast<uint8_t>(a & 0x0F);
  uint8_t right = static_cast<uint8_t>(b & 0x0F);
  for (int bit = 0; bit < 4; ++bit) {
    if (right & 1u) {
      result ^= left;
    }
    const bool carry = (left & 0x08u) != 0;
    left = static_cast<uint8_t>((left << 1) & 0x0F);
    if (carry) {
      left ^= 0x03u;  // x^4 = x + 1
    }
    right >>= 1;
  }
  return result;
}

size_t MatrixEntries(const SnovaParams &params) { return params.sq_rank; }

uint8_t *MatrixAt(std::vector<uint8_t> *storage, const SnovaParams &params, size_t index) {
  return storage->data() + index * MatrixEntries(params);
}

const uint8_t *MatrixAt(const std::vector<uint8_t> &storage, const SnovaParams &params, size_t index) {
  return storage.data() + index * MatrixEntries(params);
}

void MatMul(const uint8_t *a, const uint8_t *b, uint8_t *c, size_t l) {
  for (size_t i = 0; i < l; ++i) {
    for (size_t j = 0; j < l; ++j) {
      uint8_t acc = 0;
      for (size_t k = 0; k < l; ++k) {
        acc ^= Gf16Mul(a[i * l + k], b[k * l + j]);
      }
      c[i * l + j] = acc;
    }
  }
}

void MatTranspose(const uint8_t *a, uint8_t *out, size_t l) {
  for (size_t i = 0; i < l; ++i) {
    for (size_t j = 0; j < l; ++j) {
      out[i * l + j] = a[j * l + i];
    }
  }
}

void MatAddInPlace(uint8_t *dst, const uint8_t *src, size_t l) {
  for (size_t i = 0; i < l * l; ++i) {
    dst[i] ^= src[i];
  }
}

void MatSetZero(uint8_t *dst, size_t l) { std::memset(dst, 0, l * l); }

uint8_t NibbleAt(const uint8_t *data, size_t nibble_index) {
  const uint8_t byte = data[nibble_index / 2];
  return (nibble_index % 2 == 0) ? static_cast<uint8_t>(byte & 0x0F) : static_cast<uint8_t>((byte >> 4) & 0x0F);
}

// Reads one l x l matrix from a packed low-nibble-first stream at the given
// nibble offset.
void ReadMatrix(const uint8_t *data, size_t nibble_off, size_t l, uint8_t *out) {
  for (size_t i = 0; i < l * l; ++i) {
    out[i] = NibbleAt(data, nibble_off + i);
  }
}

}  // namespace

bool SnovaTargetHashBytes(
    const SnovaParams &params,
    const uint8_t *spublic,
    size_t spublic_len,
    const uint8_t *digest,
    size_t digest_len,
    const uint8_t *salt,
    size_t salt_len,
    std::vector<uint8_t> *out) {
  if (spublic == nullptr || digest == nullptr || salt == nullptr || out == nullptr) {
    return false;
  }
  std::vector<uint8_t> material;
  material.reserve(spublic_len + digest_len + salt_len);
  material.insert(material.end(), spublic, spublic + spublic_len);
  material.insert(material.end(), digest, digest + digest_len);
  material.insert(material.end(), salt, salt + salt_len);
  *out = Shake256(material, params.hash_bytes);
  return out->size() == params.hash_bytes;
}

bool SnovaEvaluateExpandedPk(
    const SnovaParams &params,
    const std::vector<uint8_t> &expanded_pk,
    const std::vector<uint8_t> &signature,
    std::vector<uint8_t> *out) {
  if (out == nullptr || expanded_pk.size() != params.expanded_pk_len) {
    return false;
  }
  const size_t l = params.l;
  const size_t lsq = params.sq_rank;
  const size_t m = params.m_matrices;
  const size_t n = params.n_matrices;
  const size_t alpha_count = params.alpha_terms;
  if (signature.size() < params.signature_data_bytes) {
    return false;
  }
  const uint8_t *expanded = expanded_pk.data() + params.public_seed_bytes;
  const uint8_t *sig_data = signature.data() + params.u_off;

  // Decode U (n matrices) and the expanded public map (P22,P11,P12,P21,A,B,Q1,Q2).
  std::vector<uint8_t> u_storage(static_cast<size_t>(n) * lsq);
  for (size_t si = 0; si < n; ++si) {
    ReadMatrix(sig_data, si * lsq, l, MatrixAt(&u_storage, params, si));
  }
  std::vector<uint8_t> p11(static_cast<size_t>(m) * params.v * params.v * lsq);
  std::vector<uint8_t> p12(static_cast<size_t>(m) * params.v * params.o * lsq);
  std::vector<uint8_t> p21(static_cast<size_t>(m) * params.o * params.v * lsq);
  std::vector<uint8_t> p22(static_cast<size_t>(m) * params.o * params.o * lsq);
  std::vector<uint8_t> abq(static_cast<size_t>(4) * m * alpha_count * lsq);

  const size_t p22_matrices = m * params.o * params.o;
  const size_t p11_matrices = m * params.v * params.v;
  const size_t p12_matrices = m * params.v * params.o;
  const size_t p21_matrices = m * params.o * params.v;
  const size_t abq_matrices_each = m * alpha_count;
  const size_t p11_off = params.expand_p11_nibble_off;
  const size_t p12_off = params.expand_p12_nibble_off;
  const size_t p21_off = params.expand_p21_nibble_off;
  const size_t a_off = params.expand_a_nibble_off;
  const size_t b_off = params.expand_b_nibble_off;
  const size_t q1_off = params.expand_q1_nibble_off;
  const size_t q2_off = params.expand_q2_nibble_off;
  const size_t expanded_nibbles = params.expanded_data_nibbles;

  const size_t p22_nibble_off = params.expand_p22_nibble_off;
  for (size_t index = 0; index < p22_matrices * lsq; ++index) {
    p22[index] = NibbleAt(expanded, p22_nibble_off + index);
  }
  for (size_t index = 0; index < p11_matrices * lsq; ++index) {
    p11[index] = NibbleAt(expanded, p11_off + index);
  }
  for (size_t index = 0; index < p12_matrices * lsq; ++index) {
    p12[index] = NibbleAt(expanded, p12_off + index);
  }
  for (size_t index = 0; index < p21_matrices * lsq; ++index) {
    p21[index] = NibbleAt(expanded, p21_off + index);
  }
  for (size_t index = 0; index < 4 * abq_matrices_each * lsq; ++index) {
    // A, B, Q1, Q2 are contiguous in the expanded stream.
    abq[index] = NibbleAt(expanded, a_off + index);
  }
  (void)expanded_nibbles;

  // P[mi][ni][nj]: full n x n block matrix assembled from P11/P12/P21/P22.
  std::vector<uint8_t> p_storage(static_cast<size_t>(m) * n * n * lsq, 0);
  auto block = [&](size_t mi, size_t ni, size_t nj) -> uint8_t * {
    return p_storage.data() + ((mi * n + ni) * n + nj) * lsq;
  };
  for (size_t mi = 0; mi < m; ++mi) {
    for (size_t ni = 0; ni < params.v; ++ni) {
      for (size_t nj = 0; nj < params.v; ++nj) {
        std::memcpy(block(mi, ni, nj), &p11[((mi * params.v + ni) * params.v + nj) * lsq], lsq);
      }
      for (size_t nj = params.v; nj < n; ++nj) {
        std::memcpy(block(mi, ni, nj),
                    &p12[((mi * params.v + ni) * params.o + (nj - params.v)) * lsq], lsq);
      }
    }
    for (size_t ni = params.v; ni < n; ++ni) {
      for (size_t nj = 0; nj < params.v; ++nj) {
        std::memcpy(block(mi, ni, nj),
                    &p21[((mi * params.o + (ni - params.v)) * params.v + nj) * lsq], lsq);
      }
      for (size_t nj = params.v; nj < n; ++nj) {
        std::memcpy(block(mi, ni, nj),
                    &p22[((mi * params.o + (ni - params.v)) * params.o + (nj - params.v)) * lsq], lsq);
      }
    }
  }

  // Left[mi][alpha][si] = A[mi][alpha] * (U[si]^T * Q1[mi][alpha])
  // Right[mi][alpha][si] = (Q2[mi][alpha] * U[si]) * B[mi][alpha]
  std::vector<uint8_t> left(static_cast<size_t>(m) * alpha_count * n * lsq);
  std::vector<uint8_t> right(static_cast<size_t>(m) * alpha_count * n * lsq);
  std::vector<uint8_t> temp_a(lsq);
  std::vector<uint8_t> temp_b(lsq);
  std::vector<uint8_t> u_transpose(lsq);
  for (size_t mi = 0; mi < m; ++mi) {
    for (size_t si = 0; si < n; ++si) {
      MatTranspose(MatrixAt(u_storage, params, si), u_transpose.data(), l);
      for (size_t alpha = 0; alpha < alpha_count; ++alpha) {
        const size_t abq_base = (mi * alpha_count + alpha) * lsq;
        const uint8_t *a = abq.data() + 0 * abq_matrices_each * lsq + abq_base;
        const uint8_t *b = abq.data() + 1 * abq_matrices_each * lsq + abq_base;
        const uint8_t *q1 = abq.data() + 2 * abq_matrices_each * lsq + abq_base;
        const uint8_t *q2 = abq.data() + 3 * abq_matrices_each * lsq + abq_base;
        uint8_t *left_out = left.data() + ((mi * alpha_count + alpha) * n + si) * lsq;
        uint8_t *right_out = right.data() + ((mi * alpha_count + alpha) * n + si) * lsq;
        MatMul(u_transpose.data(), q1, temp_a.data(), l);
        MatMul(a, temp_a.data(), left_out, l);
        MatMul(q2, MatrixAt(u_storage, params, si), temp_b.data(), l);
        MatMul(temp_b.data(), b, right_out, l);
      }
    }
  }

  // out[mi] = sum_alpha sum_ni Left[mi][alpha][ni] *
  //           (sum_nj P[(mi+alpha)%m][ni][nj] * Right[mi][alpha][nj])
  std::vector<uint8_t> out_matrices(static_cast<size_t>(m) * lsq, 0);
  std::vector<uint8_t> sum_t0(lsq);
  std::vector<uint8_t> product(lsq);
  for (size_t mi = 0; mi < m; ++mi) {
    uint8_t *out_mi = out_matrices.data() + mi * lsq;
    MatSetZero(out_mi, l);
    for (size_t alpha = 0; alpha < alpha_count; ++alpha) {
      const size_t mi_prime = (mi + alpha) % m;
      for (size_t ni = 0; ni < n; ++ni) {
        MatSetZero(sum_t0.data(), l);
        for (size_t nj = 0; nj < n; ++nj) {
          MatMul(block(mi_prime, ni, nj),
                 right.data() + ((mi * alpha_count + alpha) * n + nj) * lsq, product.data(), l);
          MatAddInPlace(sum_t0.data(), product.data(), l);
        }
        MatMul(left.data() + ((mi * alpha_count + alpha) * n + ni) * lsq, sum_t0.data(), product.data(), l);
        MatAddInPlace(out_mi, product.data(), l);
      }
    }
  }

  // Pack the m*l*l nibbles low-nibble-first.
  out->assign(params.hash_bytes, 0);
  for (size_t index = 0; index < m * lsq; ++index) {
    const uint8_t nibble = out_matrices[index];
    if (index % 2 == 0) {
      (*out)[index / 2] = static_cast<uint8_t>((*out)[index / 2] & 0xF0) | (nibble & 0x0F);
    } else {
      (*out)[index / 2] = static_cast<uint8_t>((*out)[index / 2] & 0x0F) | ((nibble & 0x0F) << 4);
    }
  }
  return true;
}

bool SnovaMapBytesEqual(
    const SnovaParams &params,
    const std::vector<uint8_t> &map_bytes,
    const std::vector<uint8_t> &target_hash) {
  if (map_bytes.size() != params.hash_bytes || target_hash.size() != params.hash_bytes) {
    return false;
  }
  const bool odd = (params.hash_nibbles % 2) == 1;
  for (size_t i = 0; i < params.hash_bytes; ++i) {
    uint8_t expected = target_hash[i];
    if (odd && i + 1 == params.hash_bytes) {
      expected = static_cast<uint8_t>(expected & 0x0F);
    }
    if (map_bytes[i] != expected) {
      return false;
    }
  }
  return true;
}

}  // namespace pqcfuzz
