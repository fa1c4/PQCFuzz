#ifndef PQCFUZZ_RUNTIME_EXIT_CODES_H
#define PQCFUZZ_RUNTIME_EXIT_CODES_H

namespace pqcfuzz {

constexpr int kExitNoFinding = 0;
constexpr int kExitCryptoOracleViolation = 70;
constexpr int kExitHang = 71;
constexpr int kExitNativeCrash = 72;
constexpr int kExitUnsupported = 73;
constexpr int kExitInvalidInputOrConfig = 74;

}  // namespace pqcfuzz

#endif
