#include "module.h"

#include <cryptofuzz/crypto.h>
#include <cryptofuzz/util.h>

#include "../../liboqs_replay_input.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <oqs/oqs.h>
#include <oqs/rand.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

/*
 * Shared oracle policy:
 *
 * This file is intentionally byte-for-byte mirrored in
 * baselines/CLFuzz/modules/liboqs/module.cpp.  The two fuzzers retain their
 * own executor and mutator behaviour, while this local liboqs oracle and its
 * sidecar finding format stay identical.  See baselines/PATCHES.md and the
 * shared-module policy test for the synchronization guard.
 */

#ifndef PQCDF_LIBOQS_MODULE_VERSION
#define PQCDF_LIBOQS_MODULE_VERSION "pqcdf-liboqs-oracle-v2"
#endif

namespace cryptofuzz {
namespace module {

namespace {

/* The oracle is physically shared by cryptofuzz and CLFuzz, so its sidecar
 * contract uses neutral names.  The legacy cryptofuzz names remain accepted
 * to keep already-built integrations and replay tooling compatible. */
constexpr const char *kFindingsDirectoryEnv = "PQCDF_LIBOQS_FINDINGS_DIR";
constexpr const char *kDiagnosticsDirectoryEnv = "PQCDF_LIBOQS_DIAGNOSTICS_DIR";
constexpr const char *kMetadataDirectoryEnv = "PQCDF_LIBOQS_METADATA_DIR";
constexpr const char *kOutcomesDirectoryEnv = "PQCDF_LIBOQS_OUTCOMES_DIR";
constexpr const char *kMaxExemplarsEnv = "PQCDF_LIBOQS_MAX_EXEMPLARS_PER_GROUP";
constexpr const char *kModuleVersionEnv = "PQCDF_LIBOQS_MODULE_VERSION";
constexpr const char *kLiboqsVersionEnv = "PQCDF_LIBOQS_VERSION";
constexpr const char *kLogFileEnv = "PQCDF_LIBOQS_LOG_FILE";
constexpr const char *kBaselineEnv = "PQCDF_LIBOQS_BASELINE";
constexpr const char *kLegacyFindingsDirectoryEnv = "PQCDF_CRYPTOFUZZ_FINDINGS_DIR";
constexpr const char *kLegacyDiagnosticsDirectoryEnv = "PQCDF_CRYPTOFUZZ_DIAGNOSTICS_DIR";
constexpr const char *kLegacyMetadataDirectoryEnv = "PQCDF_CRYPTOFUZZ_METADATA_DIR";
constexpr const char *kLegacyOutcomesDirectoryEnv = "PQCDF_CRYPTOFUZZ_OUTCOMES_DIR";
constexpr const char *kLegacyMaxExemplarsEnv = "PQCDF_CRYPTOFUZZ_MAX_EXEMPLARS_PER_GROUP";
constexpr const char *kLegacyModuleVersionEnv = "PQCDF_CRYPTOFUZZ_MODULE_VERSION";
constexpr const char *kLegacyLiboqsVersionEnv = "PQCDF_CRYPTOFUZZ_LIBOQS_VERSION";
constexpr const char *kLegacyLogFileEnv = "PQCDF_CRYPTOFUZZ_LOG_FILE";
constexpr const char *kReplayModeEnv = "PQCDF_LIBOQS_REPLAY_MODE";
constexpr const char *kReplayAlgorithmEnv = "PQCDF_LIBOQS_REPLAY_ALGORITHM";
constexpr const char *kReplayPropertyEnv = "PQCDF_LIBOQS_REPLAY_PROPERTY";
constexpr const char *kMutationSemanticsEnv = "PQCDF_LIBOQS_MUTATION_SEMANTICS";
constexpr const char *kReplayAttemptsEnv = "PQCDF_LIBOQS_REPLAY_ATTEMPTS";
constexpr const char *kReplayInputSHA256Env = "PQCDF_LIBOQS_REPLAY_INPUT_SHA256";
constexpr const char *kReplayInputPathEnv = "PQCDF_LIBOQS_REPLAY_INPUT_RELATIVE_PATH";

static uint64_t rngState = 0;
static uint64_t temporaryFileCounter = 0;

uint64_t Mix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

void DeterministicRandomBytes(uint8_t *out, size_t outLen) {
    size_t off = 0;
    while ( off < outLen ) {
        rngState = Mix64(rngState);
        const uint64_t block = rngState;
        const size_t n = std::min(outLen - off, sizeof(block));
        std::memcpy(out + off, &block, n);
        off += n;
    }
}

void SetDeterministicRandom(const std::vector<uint8_t>& entropy, uint64_t selector,
                            const char *domain) {
    uint64_t state = 0x6a09e667f3bcc909ULL ^ selector;

    for (const auto byte : entropy) {
        state ^= byte;
        state *= 0x100000001b3ULL;
    }
    for (const char *p = domain; *p != '\0'; p++) {
        state ^= static_cast<uint8_t>(*p);
        state *= 0x100000001b3ULL;
    }

    rngState = Mix64(state);
    OQS_randombytes_custom_algorithm(DeterministicRandomBytes);
}

uint64_t FNV1a(const uint8_t *data, size_t size, uint64_t state) {
    for (size_t i = 0; i < size; i++) {
        state ^= data[i];
        state *= 1099511628211ULL;
    }
    return state;
}

std::string DigestHex(const uint8_t *data, size_t size) {
    const uint64_t left = FNV1a(data, size, 1469598103934665603ULL);
    uint64_t right = FNV1a(data, size, 1099511628211ULL ^ static_cast<uint64_t>(size));
    right = FNV1a(reinterpret_cast<const uint8_t *>(&left), sizeof(left), right);
    char digest[33];
    std::snprintf(digest, sizeof(digest), "%016llx%016llx",
                  static_cast<unsigned long long>(left), static_cast<unsigned long long>(right));
    return digest;
}

std::string DigestHex(const std::string& value) {
    return DigestHex(reinterpret_cast<const uint8_t *>(value.data()), value.size());
}

std::string DigestHex(const std::vector<uint8_t>& value) {
    return DigestHex(value.data(), value.size());
}

struct MutationResult {
    bool effective = false;
    size_t offset = 0;
    size_t length = 0;
    std::string operation = "none";
    std::string semantics = "current-xor-v1";
    std::string deltaHex = "00";
    std::string beforeDigest = "not_applicable";
    std::string afterDigest = "not_applicable";
};

bool ReplayModeEnabled() {
    const char *mode = std::getenv(kReplayModeEnv);
    return mode != nullptr && std::strcmp(mode, "raw-input-v1") == 0;
}

std::string ByteHex(uint8_t value) {
    char encoded[3];
    std::snprintf(encoded, sizeof(encoded), "%02x", static_cast<unsigned>(value));
    return encoded;
}

MutationResult MutateAt(std::vector<uint8_t>& data, size_t pos, uint8_t delta,
                        const char *operation = "xor", const char *semantics = "current-xor-v1") {
    MutationResult result;
    result.operation = operation;
    result.semantics = semantics;
    result.deltaHex = ByteHex(delta);
    result.offset = pos;
    result.beforeDigest = DigestHex(data);
    result.afterDigest = result.beforeDigest;
    if ( data.empty() || pos >= data.size() || delta == 0 ) {
        return result;
    }

    const uint8_t original = data[pos];
    data[pos] ^= delta;
    result.effective = data[pos] != original;
    result.offset = pos;
    result.length = result.effective ? 1 : 0;
    result.afterDigest = DigestHex(data);
    return result;
}

/* A zero byte supplied by the fuzzer is deliberately a no-op.  This makes
 * no-op plans observable and prevents them from being mistaken for accepted
 * mutations.  An empty mutation buffer retains the historical one-bit flip
 * so the operation remains useful without a separate mutation payload. */
MutationResult Mutate(std::vector<uint8_t>& data, const Buffer& mutation, uint64_t selector) {
    MutationResult result;
    if ( data.empty() ) {
        return result;
    }

    const auto mutationBytes = mutation.Get();
    const size_t pos = static_cast<size_t>(selector % data.size());
    uint8_t delta = mutationBytes.empty() ? 1 :
        mutationBytes[static_cast<size_t>(selector % mutationBytes.size())];
    const bool useLegacySemantics = ReplayModeEnabled() &&
        std::getenv(kMutationSemanticsEnv) != nullptr &&
        std::strcmp(std::getenv(kMutationSemanticsEnv), "legacy-or-one-v1") == 0;
    if ( useLegacySemantics ) {
        delta |= 1;
    }
    return MutateAt(data, pos, delta, "xor",
                    useLegacySemantics ? "legacy-or-one-v1" : "current-xor-v1");
}

MutationResult RNGMutation(const std::vector<uint8_t>& entropy, uint64_t selector, const char *domain) {
    MutationResult result;
    result.effective = true;
    result.offset = static_cast<size_t>(selector);
    result.length = sizeof(rngState);
    result.operation = "rng_stream";
    result.semantics = std::string("rng_stream_v1:") + domain;
    result.deltaHex = ByteHex(static_cast<uint8_t>(rngState));
    result.beforeDigest = DigestHex(entropy);
    result.afterDigest = DigestHex(reinterpret_cast<const uint8_t *>(&rngState), sizeof(rngState));
    return result;
}

bool VectorsEqual(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

const uint8_t *DataOrDummy(const std::vector<uint8_t>& data) {
    static const uint8_t dummy = 0;
    return data.empty() ? &dummy : data.data();
}

uint8_t *DataOrDummy(std::vector<uint8_t>& data) {
    static uint8_t dummy = 0;
    return data.empty() ? &dummy : data.data();
}

const char *StatusName(const OQS_STATUS status) {
    return status == OQS_SUCCESS ? "ok" : "operation_error";
}

struct SystemRandomResult {
    OQS_STATUS status = OQS_ERROR;
    bool switchSucceeded = false;
};

template <typename Callable>
SystemRandomResult CallWithSystemRandom(Callable callable) {
    const OQS_STATUS switchStatus = OQS_randombytes_switch_algorithm("system");
    if ( switchStatus != OQS_SUCCESS ) {
        OQS_randombytes_custom_algorithm(DeterministicRandomBytes);
        return {switchStatus, false};
    }

    const OQS_STATUS status = callable();
    OQS_randombytes_custom_algorithm(DeterministicRandomBytes);
    return {status, true};
}

std::string SystemRandomStatus(const SystemRandomResult& result) {
    return result.switchSucceeded ? StatusName(result.status) : "unsupported_rng_control";
}

enum class OutcomeKind {
    Passed,
    Skipped,
    Diagnostic,
    Finding,
};

struct Outcome {
    OutcomeKind kind = OutcomeKind::Passed;
    std::string primitive;
    std::string algorithm;
    std::string propertyId;
    std::string operation;
    std::string mutationTarget = "none";
    bool mutationEffective = false;
    size_t mutationOffset = 0;
    size_t mutationLength = 0;
    std::string mutationOperation = "none";
    std::string mutationSemantics = "current-xor-v1";
    std::string mutationDeltaHex = "00";
    std::string mutationBeforeDigest = "not_applicable";
    std::string mutationAfterDigest = "not_applicable";
    std::string operationStatus = "ok";
    std::string setupStatus = "ok";
    std::string baselineStatus = "ok";
    std::string mutatedStatus = "not_run";
    std::string expectedRelation = "not_applicable";
    std::string semanticRelation = "not_applicable";
    std::string classification = "property_passed";
    std::string findingClass = "none";
    std::string findingSubclass = "none";
    std::string diagnosticClass = "none";
    std::string normalizedObservation = "not_applicable";
    std::string controlledRngStatus = "not_run";
    std::string defaultRngStatus = "not_run";
    std::string canonicalizationStatus = "not_exposed";
    std::string publicKeyByteUse = "not_applicable";
    std::string publicKeyProbeDeltaHex = "not_run";
    std::string publicKeyProbeStatus = "not_run";
    bool replayRequired = false;
    size_t replayAttempts = 0;
    size_t replayReproduced = 0;
    std::string replayResult = "not_required";
    std::string replayAttemptResults = "[]";
    std::string diagnostic;
};

Outcome NewOutcome(OutcomeKind kind, const char *primitive, const std::string& algorithm,
                   const char *propertyId, const char *operation, const char *mutationTarget) {
    Outcome outcome;
    outcome.kind = kind;
    outcome.primitive = primitive;
    outcome.algorithm = algorithm;
    outcome.propertyId = propertyId;
    outcome.operation = operation;
    outcome.mutationTarget = mutationTarget;
    switch (kind) {
        case OutcomeKind::Passed:
            outcome.classification = "property_passed";
            break;
        case OutcomeKind::Skipped:
            outcome.classification = "skipped";
            outcome.operationStatus = "skipped";
            break;
        case OutcomeKind::Diagnostic:
            outcome.classification = "operation_diagnostic";
            outcome.operationStatus = "operation_error";
            break;
        case OutcomeKind::Finding:
            outcome.classification = "semantic_finding";
            outcome.operationStatus = "invariant_violation";
            outcome.replayRequired = true;
            outcome.replayResult = "pending";
            break;
    }
    return outcome;
}

void ApplyMutation(Outcome& outcome, const MutationResult& mutation) {
    outcome.mutationEffective = mutation.effective;
    outcome.mutationOffset = mutation.offset;
    outcome.mutationLength = mutation.length;
    outcome.mutationOperation = mutation.operation;
    outcome.mutationSemantics = mutation.semantics;
    outcome.mutationDeltaHex = mutation.deltaHex;
    outcome.mutationBeforeDigest = mutation.beforeDigest;
    outcome.mutationAfterDigest = mutation.afterDigest;
}

Outcome NoOpMutation(const char *primitive, const std::string& algorithm,
                     const char *propertyId, const char *operation, const char *target,
                     const MutationResult& mutation) {
    auto outcome = NewOutcome(OutcomeKind::Skipped, primitive, algorithm, propertyId, operation, target);
    ApplyMutation(outcome, mutation);
    outcome.mutatedStatus = "not_run";
    outcome.semanticRelation = "NO_EFFECTIVE_MUTATION";
    outcome.normalizedObservation = outcome.semanticRelation;
    outcome.diagnostic = "mutation left the original field unchanged";
    return outcome;
}

Outcome PropertyPassed(const char *primitive, const std::string& algorithm,
                       const char *propertyId, const char *operation, const char *target,
                       const MutationResult& mutation, const char *baselineStatus,
                       const char *mutatedStatus, const char *expectedRelation,
                       const char *semanticRelation) {
    auto outcome = NewOutcome(OutcomeKind::Passed, primitive, algorithm, propertyId, operation, target);
    ApplyMutation(outcome, mutation);
    outcome.baselineStatus = baselineStatus;
    outcome.mutatedStatus = mutatedStatus;
    outcome.expectedRelation = expectedRelation;
    outcome.semanticRelation = semanticRelation;
    outcome.normalizedObservation = semanticRelation;
    return outcome;
}

Outcome Finding(const char *primitive, const std::string& algorithm, const char *propertyId,
                const char *operation, const char *target, const MutationResult& mutation,
                const char *baselineStatus, const char *mutatedStatus,
                const char *expectedRelation, const char *semanticRelation,
                const char *findingClass, const char *findingSubclass) {
    auto outcome = NewOutcome(OutcomeKind::Finding, primitive, algorithm, propertyId, operation, target);
    ApplyMutation(outcome, mutation);
    outcome.baselineStatus = baselineStatus;
    outcome.mutatedStatus = mutatedStatus;
    outcome.expectedRelation = expectedRelation;
    outcome.semanticRelation = semanticRelation;
    outcome.findingClass = findingClass;
    outcome.findingSubclass = findingSubclass;
    outcome.normalizedObservation = semanticRelation;
    return outcome;
}

Outcome Diagnostic(const char *primitive, const std::string& algorithm, const char *propertyId,
                   const char *operation, const char *setupStatus, const char *baselineStatus,
                   const char *mutatedStatus, const char *diagnosticClass,
                   const char *diagnostic) {
    auto outcome = NewOutcome(OutcomeKind::Diagnostic, primitive, algorithm, propertyId,
                              operation, "none");
    outcome.setupStatus = setupStatus;
    outcome.baselineStatus = baselineStatus;
    outcome.mutatedStatus = mutatedStatus;
    outcome.diagnosticClass = diagnosticClass;
    outcome.diagnostic = diagnostic;
    outcome.semanticRelation = "not_evaluated";
    outcome.normalizedObservation = "not_evaluated";
    return outcome;
}

struct ReplayInput {
    uint64_t selector = 0;
    std::string entropyHex;
    std::string messageHex;
    std::string mutationHex;
    std::string operationJSON;
    std::string inputSHA256;
    std::string inputRelativePath;
};

std::string EscapeJSON(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (const unsigned char c : value) {
        switch (c) {
            case '"': escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if ( c < 0x20U ) {
                    char encoded[7];
                    std::snprintf(encoded, sizeof(encoded), "\\u%04x", static_cast<unsigned>(c));
                    escaped += encoded;
                } else {
                    escaped.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    escaped.push_back('"');
    return escaped;
}

bool IsDirectory(const char *path) {
    if ( path == nullptr || *path == '\0' ) {
        return false;
    }
    struct stat status {};
    return stat(path, &status) == 0 && S_ISDIR(status.st_mode);
}

const char *ConfiguredValue(const char *primary, const char *legacy = nullptr) {
    const char *configured = std::getenv(primary);
    if ( configured != nullptr && *configured != '\0' ) {
        return configured;
    }
    if ( legacy != nullptr ) {
        configured = std::getenv(legacy);
        if ( configured != nullptr && *configured != '\0' ) {
            return configured;
        }
    }
    return nullptr;
}

unsigned long MaxExemplarsPerGroup() {
    const char *configured = ConfiguredValue(kMaxExemplarsEnv, kLegacyMaxExemplarsEnv);
    if ( configured == nullptr ) {
        return 3;
    }
    char *end = nullptr;
    const unsigned long value = std::strtoul(configured, &end, 10);
    if ( end == configured || *end != '\0' || value == 0 || value > 1000 ) {
        return 3;
    }
    return value;
}

unsigned long CountGroupExemplars(const std::string& directory, const std::string& prefix) {
    DIR *handle = opendir(directory.c_str());
    if ( handle == nullptr ) {
        return 0;
    }
    unsigned long count = 0;
    while (dirent *entry = readdir(handle)) {
        const std::string name(entry->d_name);
        if ( name.size() > prefix.size() + 5 && name.compare(0, prefix.size(), prefix) == 0 &&
             name.compare(name.size() - 5, 5, ".json") == 0 ) {
            count++;
        }
    }
    (void)closedir(handle);
    return count;
}

bool WriteAtomically(const std::string& directory, const std::string& filename,
                     const std::string& content) {
    const std::string destination = directory + "/" + filename;
    const std::string temporary = directory + "/." + filename + "." +
        std::to_string(static_cast<long long>(getpid())) + "." +
        std::to_string(static_cast<unsigned long long>(++temporaryFileCounter)) + ".tmp";
    const int descriptor = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if ( descriptor < 0 ) {
        return false;
    }

    FILE *file = fdopen(descriptor, "w");
    if ( file == nullptr ) {
        (void)close(descriptor);
        (void)unlink(temporary.c_str());
        return false;
    }

    const bool wrote = std::fwrite(content.data(), 1, content.size(), file) == content.size();
    const bool flushed = wrote && std::fflush(file) == 0 && fsync(descriptor) == 0;
    const bool closed = std::fclose(file) == 0;
    if ( !flushed || !closed ) {
        (void)unlink(temporary.c_str());
        return false;
    }

    /* link(2) gives an exclusive, atomic publish: an existing digest-named
     * exemplar wins and is never overwritten by another worker. */
    const bool published = link(temporary.c_str(), destination.c_str()) == 0 || errno == EEXIST;
    (void)unlink(temporary.c_str());
    return published;
}

bool CaptureCurrentRawFixture(ReplayInput& input) {
    const auto rawInput = liboqs_replay::CurrentInput();
    if ( rawInput.data == nullptr || rawInput.size == 0 ) {
        return false;
    }
    const char *findingsDirectory = ConfiguredValue(kFindingsDirectoryEnv, kLegacyFindingsDirectoryEnv);
    if ( !IsDirectory(findingsDirectory) ) {
        return false;
    }

    const std::string fixtureSHA256 = util::BinToHex(crypto::sha256(rawInput.data, rawInput.size));
    if ( fixtureSHA256.size() != 64 ) {
        return false;
    }
    if ( !input.inputSHA256.empty() || !input.inputRelativePath.empty() ) {
        if ( input.inputSHA256.empty() || input.inputRelativePath.empty() ||
             input.inputRelativePath.front() == '/' ||
             input.inputRelativePath.find("..") != std::string::npos ||
             input.inputSHA256 != fixtureSHA256 ) {
            return false;
        }
        struct stat stagedStatus {};
        const std::string stagedPath = std::string(findingsDirectory) + "/" + input.inputRelativePath;
        return stat(stagedPath.c_str(), &stagedStatus) == 0 && S_ISREG(stagedStatus.st_mode);
    }
    const std::string fixtureDirectory = std::string(findingsDirectory) + "/replay-inputs";
    if ( mkdir(fixtureDirectory.c_str(), 0700) != 0 && errno != EEXIST ) {
        return false;
    }
    if ( !IsDirectory(fixtureDirectory.c_str()) ) {
        return false;
    }

    const std::string fixtureName = fixtureSHA256 + ".bin";
    const std::string fixtureData(reinterpret_cast<const char *>(rawInput.data), rawInput.size);
    if ( !WriteAtomically(fixtureDirectory, fixtureName, fixtureData) ) {
        return false;
    }
    input.inputSHA256 = fixtureSHA256;
    input.inputRelativePath = "replay-inputs/" + fixtureName;
    return true;
}

const char *ModuleVersion() {
    const char *configured = ConfiguredValue(kModuleVersionEnv, kLegacyModuleVersionEnv);
    return configured != nullptr ? configured : PQCDF_LIBOQS_MODULE_VERSION;
}

const char *LiboqsVersion() {
    const char *configured = ConfiguredValue(kLiboqsVersionEnv, kLegacyLiboqsVersionEnv);
    return configured != nullptr ? configured : "unknown";
}

const char *CampaignLogFile() {
    const char *configured = ConfiguredValue(kLogFileEnv, kLegacyLogFileEnv);
    return configured != nullptr ? configured : "";
}

const char *BaselineName() {
    const char *configured = ConfiguredValue(kBaselineEnv);
    return configured != nullptr ? configured : "cryptofuzz";
}

std::string BuildRecord(const Outcome& outcome, const ReplayInput& input,
                        const std::string& groupKey, const std::string& inputDigest) {
    const std::string operationJSON = input.operationJSON.empty() ? "null" : input.operationJSON;
    const char *kind = "property_passed";
    switch (outcome.kind) {
        case OutcomeKind::Passed:
            kind = "property_passed";
            break;
        case OutcomeKind::Skipped:
            kind = "skipped";
            break;
        case OutcomeKind::Diagnostic:
            kind = "operation_diagnostic";
            break;
        case OutcomeKind::Finding:
            kind = "semantic_finding";
            break;
    }
    std::string record;
    record.reserve(operationJSON.size() + 2304);
    record += "{\n  \"schema_version\": 1,\n  \"format_version\": 1,\n";
    record += "  \"kind\": " + EscapeJSON(kind) + ",\n  \"baseline\": " +
        EscapeJSON(BaselineName()) + ",\n";
    record += "  \"module\": \"liboqs\",\n  \"module_version\": " + EscapeJSON(ModuleVersion()) + ",\n";
    record += "  \"liboqs_version\": " + EscapeJSON(LiboqsVersion()) + ",\n";
    record += "  \"stdout_log\": " + EscapeJSON(CampaignLogFile()) + ",\n";
    record += "  \"stderr_log\": " + EscapeJSON(CampaignLogFile()) + ",\n";
    record += "  \"classification\": " + EscapeJSON(outcome.classification) + ",\n";
    record += "  \"primitive\": " + EscapeJSON(outcome.primitive) + ",\n";
    record += "  \"algorithm\": " + EscapeJSON(outcome.algorithm) + ",\n";
    record += "  \"property_id\": " + EscapeJSON(outcome.propertyId) + ",\n";
    record += "  \"operation\": " + EscapeJSON(outcome.operation) + ",\n";
    record += "  \"operation_status\": " + EscapeJSON(outcome.operationStatus) + ",\n";
    record += "  \"setup_status\": " + EscapeJSON(outcome.setupStatus) + ",\n";
    record += "  \"baseline_status\": " + EscapeJSON(outcome.baselineStatus) + ",\n";
    record += "  \"mutated_status\": " + EscapeJSON(outcome.mutatedStatus) + ",\n";
    record += "  \"mutation_target\": " + EscapeJSON(outcome.mutationTarget) + ",\n";
    record += "  \"mutation_effective\": ";
    record += outcome.mutationEffective ? "true,\n" : "false,\n";
    record += "  \"mutation_offset\": " + std::to_string(outcome.mutationOffset) + ",\n";
    record += "  \"mutation_length\": " + std::to_string(outcome.mutationLength) + ",\n";
    record += "  \"mutation_operation\": " + EscapeJSON(outcome.mutationOperation) + ",\n";
    record += "  \"mutation_semantics\": " + EscapeJSON(outcome.mutationSemantics) + ",\n";
    record += "  \"mutation_delta_hex\": " + EscapeJSON(outcome.mutationDeltaHex) + ",\n";
    record += "  \"mutation_before_digest\": " + EscapeJSON(outcome.mutationBeforeDigest) + ",\n";
    record += "  \"mutation_after_digest\": " + EscapeJSON(outcome.mutationAfterDigest) + ",\n";
    record += "  \"expected_relation\": " + EscapeJSON(outcome.expectedRelation) + ",\n";
    record += "  \"semantic_relation\": " + EscapeJSON(outcome.semanticRelation) + ",\n";
    record += "  \"normalized_observation\": " + EscapeJSON(outcome.normalizedObservation) + ",\n";
    record += "  \"finding_class\": " + EscapeJSON(outcome.findingClass) + ",\n";
    record += "  \"finding_subclass\": " + EscapeJSON(outcome.findingSubclass) + ",\n";
    record += "  \"diagnostic_class\": " + EscapeJSON(outcome.diagnosticClass) + ",\n";
    record += "  \"diagnostic\": " + EscapeJSON(outcome.diagnostic) + ",\n";
    record += "  \"controlled_rng_status\": " + EscapeJSON(outcome.controlledRngStatus) + ",\n";
    record += "  \"default_rng_status\": " + EscapeJSON(outcome.defaultRngStatus) + ",\n";
    record += "  \"canonicalization_status\": " + EscapeJSON(outcome.canonicalizationStatus) + ",\n";
    record += "  \"public_key_byte_use\": " + EscapeJSON(outcome.publicKeyByteUse) + ",\n";
    record += "  \"public_key_probe_delta_hex\": " + EscapeJSON(outcome.publicKeyProbeDeltaHex) + ",\n";
    record += "  \"public_key_probe_status\": " + EscapeJSON(outcome.publicKeyProbeStatus) + ",\n";
    record += "  \"dedup_key\": " + EscapeJSON(groupKey) + ",\n";
    record += "  \"input_digest\": " + EscapeJSON(inputDigest) + ",\n";
    record += "  \"input\": {\n    \"selector\": " +
        std::to_string(static_cast<unsigned long long>(input.selector)) + ",\n";
    record += "    \"entropy_hex\": " + EscapeJSON(input.entropyHex) + ",\n";
    record += "    \"message_hex\": " + EscapeJSON(input.messageHex) + ",\n";
    record += "    \"mutation_hex\": " + EscapeJSON(input.mutationHex) + ",\n";
    record += "    \"fixture_sha256\": " + EscapeJSON(input.inputSHA256) + ",\n";
    record += "    \"fixture_path\": " + EscapeJSON(input.inputRelativePath) + ",\n";
    record += "    \"operation\": " + operationJSON + "\n  },\n";
    record += "  \"original_input\": { \"operation\": " + operationJSON + " },\n";
    record += "  \"minimized_input\": { \"minimized\": false, \"operation\": " + operationJSON + " },\n";
    record += "  \"replay\": {\n    \"required\": ";
    record += outcome.replayRequired ? "true,\n" : "false,\n";
    record += "    \"result\": " + EscapeJSON(outcome.replayResult) + ",\n";
    record += "    \"attempts_required\": " + std::to_string(outcome.replayAttempts) + ",\n";
    record += "    \"attempts_completed\": " + std::to_string(outcome.replayAttempts) + ",\n";
    record += "    \"reproduced_count\": " + std::to_string(outcome.replayReproduced) + ",\n";
    record += "    \"attempt_results\": " + outcome.replayAttemptResults + ",\n";
    record += "    \"input_sha256\": " + EscapeJSON(input.inputSHA256) + ",\n";
    record += "    \"input_path\": " + EscapeJSON(input.inputRelativePath) + ",\n";
    record += "    \"algorithm\": " + EscapeJSON(outcome.algorithm) + ",\n";
    record += "    \"property_id\": " + EscapeJSON(outcome.propertyId) + ",\n";
    record += "    \"semantic_relation\": " + EscapeJSON(outcome.semanticRelation) + "\n  }\n}\n";
    return record;
}

bool WriteOutcome(const Outcome& outcome, const ReplayInput& input) {
    const char *directoryValue = nullptr;
    const char *filePrefix = "outcome-";
    switch (outcome.kind) {
        case OutcomeKind::Finding:
            directoryValue = ConfiguredValue(kFindingsDirectoryEnv, kLegacyFindingsDirectoryEnv);
            filePrefix = "finding-";
            break;
        case OutcomeKind::Diagnostic:
            directoryValue = ConfiguredValue(kDiagnosticsDirectoryEnv, kLegacyDiagnosticsDirectoryEnv);
            filePrefix = "diagnostic-";
            break;
        case OutcomeKind::Passed:
        case OutcomeKind::Skipped:
            directoryValue = ConfiguredValue(kOutcomesDirectoryEnv, kLegacyOutcomesDirectoryEnv);
            break;
    }
    if ( !IsDirectory(directoryValue) ) {
        return false;
    }
    const std::string directory(directoryValue);
    const std::string groupKey = outcome.primitive + "|" + outcome.algorithm + "|" +
        outcome.propertyId + "|" + outcome.mutationTarget + "|" + outcome.semanticRelation + "|" +
        outcome.findingClass + "|" + outcome.findingSubclass + "|" + outcome.diagnosticClass;
    const std::string groupDigest = DigestHex(groupKey);
    const std::string inputDigest = DigestHex(input.operationJSON);
    const std::string namePrefix = filePrefix + groupDigest + "-";
    const std::string filename = namePrefix + inputDigest + ".json";
    const std::string lockPath = directory + "/.pqcdf-" + filePrefix + groupDigest + ".lock";

    bool haveLock = false;
    for (size_t attempt = 0; attempt < 100; attempt++) {
        if ( mkdir(lockPath.c_str(), 0700) == 0 ) {
            haveLock = true;
            break;
        }
        if ( errno != EEXIST ) {
            break;
        }
        (void)usleep(1000);
    }
    if ( !haveLock ) {
        return false;
    }

    bool written = false;
    if ( CountGroupExemplars(directory, namePrefix) < MaxExemplarsPerGroup() ) {
        written = WriteAtomically(directory, filename, BuildRecord(outcome, input, groupKey, inputDigest));
    }
    (void)rmdir(lockPath.c_str());
    return written;
}

void WriteDiagnostic(const Outcome& outcome, const ReplayInput& input) {
    if ( WriteOutcome(outcome, input) ) {
        std::printf("[liboqs] diagnostic %s %s/%s: %s\n", outcome.primitive.c_str(),
                    outcome.algorithm.c_str(), outcome.operation.c_str(), outcome.diagnostic.c_str());
    }
}

bool IsSameFinding(const Outcome& lhs, const Outcome& rhs) {
    return lhs.kind == OutcomeKind::Finding && rhs.kind == OutcomeKind::Finding &&
        lhs.primitive == rhs.primitive && lhs.algorithm == rhs.algorithm &&
        lhs.propertyId == rhs.propertyId && lhs.mutationTarget == rhs.mutationTarget &&
        lhs.semanticRelation == rhs.semanticRelation && lhs.findingClass == rhs.findingClass &&
        lhs.findingSubclass == rhs.findingSubclass;
}

struct KEMDeleter {
    void operator()(OQS_KEM *kem) const {
        OQS_KEM_free(kem);
    }
};

struct SIGDeleter {
    void operator()(OQS_SIG *sig) const {
        OQS_SIG_free(sig);
    }
};

constexpr const char *kKEMProperties[] = {
    "kem_roundtrip",
    "kem_decaps_c",
    "kem_decaps_sk",
    "kem_encaps_pk",
    "kem_keygen_badrng",
    "kem_encaps_badrng",
};

constexpr const char *kSIGProperties[] = {
    "sig_roundtrip",
    "sig_verify_sig",
    "sig_verify_m",
    "sig_verify_pk",
    "sig_sign_sk",
    "sig_keygen_badrng",
    "sig_sign_badrng",
};

std::string JSONStringArray(const std::vector<std::string>& values) {
    std::string output = "[";
    for (size_t i = 0; i < values.size(); i++) {
        if ( i != 0 ) {
            output += ", ";
        }
        output += EscapeJSON(values[i]);
    }
    output += "]";
    return output;
}

template <size_t N>
std::string JSONStringArray(const char *const (&values)[N]) {
    std::string output = "[";
    for (size_t i = 0; i < N; i++) {
        if ( i != 0 ) {
            output += ", ";
        }
        output += EscapeJSON(values[i]);
    }
    output += "]";
    return output;
}

void WriteMetadata(const std::vector<std::string>& kemAlgorithms,
                   const std::vector<std::string>& sigAlgorithms) {
    const char *directoryValue = ConfiguredValue(kMetadataDirectoryEnv, kLegacyMetadataDirectoryEnv);
    if ( !IsDirectory(directoryValue) ) {
        return;
    }

    std::string record;
    record += "{\n  \"schema_version\": 1,\n  \"format_version\": 1,\n  \"baseline\": " +
        EscapeJSON(BaselineName()) + ",\n";
    record += "  \"module\": \"liboqs\",\n  \"module_version\": " + EscapeJSON(ModuleVersion()) + ",\n";
    record += "  \"liboqs_version\": " + EscapeJSON(LiboqsVersion()) + ",\n";
    record += "  \"enabled_kem_algorithms\": " + JSONStringArray(kemAlgorithms) + ",\n";
    record += "  \"enabled_sig_algorithms\": " + JSONStringArray(sigAlgorithms) + ",\n";
    record += "  \"kem_property_ids\": " + JSONStringArray(kKEMProperties) + ",\n";
    record += "  \"sig_property_ids\": " + JSONStringArray(kSIGProperties) + "\n}\n";
    (void)WriteAtomically(directoryValue, "liboqs-oracle-metadata.json", record);
}

const char *ReplayOverride(const char *environment) {
    if ( !ReplayModeEnabled() ) {
        return nullptr;
    }
    const char *value = std::getenv(environment);
    return value != nullptr && *value != '\0' ? value : nullptr;
}

template <size_t N>
bool SelectProperty(uint64_t selector, size_t algorithmCount,
                    const char *const (&properties)[N], size_t& selected) {
    const char *forced = ReplayOverride(kReplayPropertyEnv);
    if ( forced != nullptr ) {
        for (size_t i = 0; i < N; i++) {
            if ( std::strcmp(forced, properties[i]) == 0 ) {
                selected = i;
                return true;
            }
        }
        return false;
    }
    if ( algorithmCount == 0 ) {
        return false;
    }
    /* Selector values are commonly small after corpus minimization.  Splitting
     * the selector into a mixed-radix (algorithm, property) pair reaches every
     * property for every enabled algorithm without relying on high bits. */
    selected = static_cast<size_t>((selector / algorithmCount) % N);
    return true;
}

bool SelectAlgorithm(const std::vector<std::string>& algorithms, uint64_t selector,
                     std::string& selected) {
    const char *forced = ReplayOverride(kReplayAlgorithmEnv);
    if ( forced != nullptr ) {
        const auto match = std::find(algorithms.begin(), algorithms.end(), forced);
        if ( match == algorithms.end() ) {
            return false;
        }
        selected = *match;
        return true;
    }
    selected = algorithms[static_cast<size_t>(selector % algorithms.size())];
    return true;
}

ReplayInput ReplayData(const operation::OQS_KEM_SelfTest& op) {
    ReplayInput input;
    input.selector = op.selector;
    input.entropyHex = util::BinToHex(op.entropy.Get());
    input.mutationHex = util::BinToHex(op.mutation.Get());
    input.operationJSON = op.ToJSON().dump();
    if ( ReplayModeEnabled() ) {
        const char *sha256 = std::getenv(kReplayInputSHA256Env);
        const char *path = std::getenv(kReplayInputPathEnv);
        input.inputSHA256 = sha256 != nullptr ? sha256 : "";
        input.inputRelativePath = path != nullptr ? path : "";
    }
    return input;
}

ReplayInput ReplayData(const operation::OQS_SIG_SelfTest& op) {
    ReplayInput input;
    input.selector = op.selector;
    input.entropyHex = util::BinToHex(op.entropy.Get());
    input.messageHex = util::BinToHex(op.message.Get());
    input.mutationHex = util::BinToHex(op.mutation.Get());
    input.operationJSON = op.ToJSON().dump();
    if ( ReplayModeEnabled() ) {
        const char *sha256 = std::getenv(kReplayInputSHA256Env);
        const char *path = std::getenv(kReplayInputPathEnv);
        input.inputSHA256 = sha256 != nullptr ? sha256 : "";
        input.inputRelativePath = path != nullptr ? path : "";
    }
    return input;
}

Outcome ControlledDiagnostic(const char *primitive, const std::string& algorithm,
                             const char *propertyId, const char *operation,
                             const char *baselineStatus, const char *diagnostic,
                             OQS_STATUS controlledStatus, const SystemRandomResult& defaultResult) {
    const std::string defaultStatus = SystemRandomStatus(defaultResult);
    const char *classification = defaultStatus == "ok" ?
        "controlled_rng_operation_failure" :
        (defaultStatus == "unsupported_rng_control" ? "rng_control_unavailable" : "operation_failure");
    auto outcome = Diagnostic(primitive, algorithm, propertyId, operation, "ok", baselineStatus,
                              "not_run", classification, diagnostic);
    outcome.controlledRngStatus = StatusName(controlledStatus);
    outcome.defaultRngStatus = defaultStatus;
    return outcome;
}

std::vector<Outcome> EvaluateKEM(OQS_KEM *kem, const std::string& algorithm,
                                 const operation::OQS_KEM_SelfTest& op, size_t algorithmCount) {
    std::vector<Outcome> outcomes;
    size_t property = 0;
    if ( !SelectProperty(op.selector, algorithmCount, kKEMProperties, property) ) {
        outcomes.push_back(Diagnostic("kem", algorithm, "replay_selection", "selection", "ok", "not_run",
            "not_run", "unsupported_replay_property", "requested replay property is not a KEM property"));
        return outcomes;
    }
    const char *propertyId = kKEMProperties[property];
    const auto entropy = op.entropy.Get();

    std::vector<uint8_t> publicKey(kem->length_public_key);
    std::vector<uint8_t> secretKey(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);
    std::vector<uint8_t> decapsSharedSecret(kem->length_shared_secret);

    SetDeterministicRandom(entropy, op.selector, "kem-keypair");
    const OQS_STATUS keypairStatus = OQS_KEM_keypair(kem, DataOrDummy(publicKey), DataOrDummy(secretKey));
    if ( keypairStatus != OQS_SUCCESS ) {
        SetDeterministicRandom(entropy, op.selector, "kem-keypair");
        const OQS_STATUS controlled = OQS_KEM_keypair(kem, DataOrDummy(publicKey), DataOrDummy(secretKey));
        const auto system = CallWithSystemRandom([&]() {
            return OQS_KEM_keypair(kem, DataOrDummy(publicKey), DataOrDummy(secretKey));
        });
        outcomes.push_back(ControlledDiagnostic("kem", algorithm, "kem_roundtrip", "keypair",
            StatusName(keypairStatus), "keypair failed for a generated test case", controlled, system));
        return outcomes;
    }

    SetDeterministicRandom(entropy, op.selector, "kem-encaps");
    const OQS_STATUS encapsStatus = OQS_KEM_encaps(kem, DataOrDummy(ciphertext),
                                                    DataOrDummy(sharedSecret), DataOrDummy(publicKey));
    if ( encapsStatus != OQS_SUCCESS ) {
        SetDeterministicRandom(entropy, op.selector, "kem-encaps");
        const OQS_STATUS controlled = OQS_KEM_encaps(kem, DataOrDummy(ciphertext),
            DataOrDummy(sharedSecret), DataOrDummy(publicKey));
        const auto system = CallWithSystemRandom([&]() {
            return OQS_KEM_encaps(kem, DataOrDummy(ciphertext), DataOrDummy(sharedSecret),
                                  DataOrDummy(publicKey));
        });
        outcomes.push_back(ControlledDiagnostic("kem", algorithm, "kem_roundtrip", "encaps",
            StatusName(encapsStatus), "encapsulation failed for a generated public key", controlled, system));
        return outcomes;
    }

    const OQS_STATUS decapsStatus = OQS_KEM_decaps(kem, DataOrDummy(decapsSharedSecret),
        DataOrDummy(ciphertext), DataOrDummy(secretKey));
    if ( decapsStatus != OQS_SUCCESS ) {
        outcomes.push_back(Diagnostic("kem", algorithm, "kem_roundtrip", "decaps", "ok",
            StatusName(decapsStatus), "not_run", "operation_failure",
            "decapsulation failed for a generated ciphertext and secret key"));
        return outcomes;
    }

    if ( !VectorsEqual(sharedSecret, decapsSharedSecret) ) {
        outcomes.push_back(Finding("kem", algorithm, "kem_roundtrip", "decaps", "roundtrip",
            {}, "ok", "ok", "EXPECT_EQUAL", "OBSERVED_DIFFERENT", "functional",
            "functional_roundtrip_failure"));
        return outcomes;
    }

    if ( property == 0 ) {
        outcomes.push_back(PropertyPassed("kem", algorithm, propertyId, "decaps", "roundtrip", {},
            "ok", "ok", "EXPECT_EQUAL", "OBSERVED_EQUAL"));
        return outcomes;
    }

    if ( property == 1 ) {
        auto mutatedCiphertext = ciphertext;
        const auto mutation = Mutate(mutatedCiphertext, op.mutation, op.selector);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("kem", algorithm, propertyId, "decaps", "ciphertext", mutation));
            return outcomes;
        }
        std::vector<uint8_t> mutatedSharedSecret(kem->length_shared_secret);
        const OQS_STATUS status = OQS_KEM_decaps(kem, DataOrDummy(mutatedSharedSecret),
            DataOrDummy(mutatedCiphertext), DataOrDummy(secretKey));
        if ( kem->ind_cca && status == OQS_SUCCESS && VectorsEqual(sharedSecret, mutatedSharedSecret) ) {
            outcomes.push_back(Finding("kem", algorithm, propertyId, "decaps", "ciphertext", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability",
                "ciphertext_malleability"));
        } else if ( kem->ind_cca ) {
            outcomes.push_back(PropertyPassed("kem", algorithm, propertyId, "decaps", "ciphertext", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", status == OQS_SUCCESS ?
                "OBSERVED_DIFFERENT" : "OBSERVED_REJECTED"));
        } else {
            auto outcome = PropertyPassed("kem", algorithm, propertyId, "decaps", "ciphertext", mutation,
                "ok", StatusName(status), "not_applicable_ind_cpa", "NOT_APPLICABLE_IND_CPA");
            outcome.kind = OutcomeKind::Skipped;
            outcome.classification = "skipped";
            outcome.operationStatus = "skipped";
            outcomes.push_back(std::move(outcome));
        }
        return outcomes;
    }

    if ( property == 2 ) {
        auto mutatedSecretKey = secretKey;
        const auto mutation = Mutate(mutatedSecretKey, op.mutation, op.selector + 1);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("kem", algorithm, propertyId, "decaps", "secret_key", mutation));
            return outcomes;
        }
        std::vector<uint8_t> mutatedSharedSecret(kem->length_shared_secret);
        const OQS_STATUS status = OQS_KEM_decaps(kem, DataOrDummy(mutatedSharedSecret),
            DataOrDummy(ciphertext), DataOrDummy(mutatedSecretKey));
        if ( status == OQS_SUCCESS && VectorsEqual(sharedSecret, mutatedSharedSecret) ) {
            outcomes.push_back(Finding("kem", algorithm, propertyId, "decaps", "secret_key", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability",
                "secret_key_malleability"));
        } else {
            outcomes.push_back(PropertyPassed("kem", algorithm, propertyId, "decaps", "secret_key", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", status == OQS_SUCCESS ?
                "OBSERVED_DIFFERENT" : "OBSERVED_REJECTED"));
        }
        return outcomes;
    }

    if ( property == 3 ) {
        auto mutatedPublicKey = publicKey;
        const auto mutation = Mutate(mutatedPublicKey, op.mutation, op.selector + 2);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("kem", algorithm, propertyId, "encaps", "public_key", mutation));
            return outcomes;
        }
        std::vector<uint8_t> alternateCiphertext(kem->length_ciphertext);
        std::vector<uint8_t> alternateSharedSecret(kem->length_shared_secret);
        SetDeterministicRandom(entropy, op.selector, "kem-encaps");
        const OQS_STATUS status = OQS_KEM_encaps(kem, DataOrDummy(alternateCiphertext),
            DataOrDummy(alternateSharedSecret), DataOrDummy(mutatedPublicKey));
        if ( status == OQS_SUCCESS && VectorsEqual(ciphertext, alternateCiphertext) &&
             VectorsEqual(sharedSecret, alternateSharedSecret) ) {
            outcomes.push_back(Finding("kem", algorithm, propertyId, "encaps", "public_key", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability",
                "public_key_ignored_or_malleable"));
        } else {
            outcomes.push_back(PropertyPassed("kem", algorithm, propertyId, "encaps", "public_key", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", status == OQS_SUCCESS ?
                "OBSERVED_DIFFERENT" : "OBSERVED_REJECTED"));
        }
        return outcomes;
    }

    if ( property == 4 ) {
        std::vector<uint8_t> alternatePublicKey(kem->length_public_key);
        std::vector<uint8_t> alternateSecretKey(kem->length_secret_key);
        SetDeterministicRandom(entropy, op.selector, "kem-keypair-rng-variant");
        const OQS_STATUS status = OQS_KEM_keypair(kem, DataOrDummy(alternatePublicKey),
            DataOrDummy(alternateSecretKey));
        const MutationResult rngMutation = RNGMutation(entropy, op.selector, "kem-keypair-rng-variant");
        if ( status != OQS_SUCCESS ) {
            SetDeterministicRandom(entropy, op.selector, "kem-keypair-rng-variant");
            const OQS_STATUS controlled = OQS_KEM_keypair(kem, DataOrDummy(alternatePublicKey),
                DataOrDummy(alternateSecretKey));
            const auto system = CallWithSystemRandom([&]() {
                return OQS_KEM_keypair(kem, DataOrDummy(alternatePublicKey), DataOrDummy(alternateSecretKey));
            });
            auto outcome = ControlledDiagnostic("kem", algorithm, propertyId, "keypair_rng_variant", "ok",
                "keypair failed with a distinct controlled RNG stream", controlled, system);
            outcome.mutationTarget = "rng_keypair";
            ApplyMutation(outcome, rngMutation);
            outcomes.push_back(std::move(outcome));
        } else if ( VectorsEqual(publicKey, alternatePublicKey) && VectorsEqual(secretKey, alternateSecretKey) ) {
            outcomes.push_back(Finding("kem", algorithm, propertyId, "keypair", "rng_keypair", rngMutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability", "keygen_rng_ignored"));
        } else {
            outcomes.push_back(PropertyPassed("kem", algorithm, propertyId, "keypair", "rng_keypair", rngMutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_DIFFERENT"));
        }
        return outcomes;
    }

    std::vector<uint8_t> alternateCiphertext(kem->length_ciphertext);
    std::vector<uint8_t> alternateSharedSecret(kem->length_shared_secret);
    SetDeterministicRandom(entropy, op.selector, "kem-encaps-rng-variant");
    const OQS_STATUS status = OQS_KEM_encaps(kem, DataOrDummy(alternateCiphertext),
        DataOrDummy(alternateSharedSecret), DataOrDummy(publicKey));
    const MutationResult rngMutation = RNGMutation(entropy, op.selector, "kem-encaps-rng-variant");
    if ( status != OQS_SUCCESS ) {
        SetDeterministicRandom(entropy, op.selector, "kem-encaps-rng-variant");
        const OQS_STATUS controlled = OQS_KEM_encaps(kem, DataOrDummy(alternateCiphertext),
            DataOrDummy(alternateSharedSecret), DataOrDummy(publicKey));
        const auto system = CallWithSystemRandom([&]() {
            return OQS_KEM_encaps(kem, DataOrDummy(alternateCiphertext),
                DataOrDummy(alternateSharedSecret), DataOrDummy(publicKey));
        });
        auto outcome = ControlledDiagnostic("kem", algorithm, propertyId, "encaps_rng_variant", "ok",
            "encapsulation failed with a distinct controlled RNG stream", controlled, system);
        outcome.mutationTarget = "rng_encaps";
        ApplyMutation(outcome, rngMutation);
        outcomes.push_back(std::move(outcome));
    } else if ( VectorsEqual(ciphertext, alternateCiphertext) && VectorsEqual(sharedSecret, alternateSharedSecret) ) {
        outcomes.push_back(Finding("kem", algorithm, propertyId, "encaps", "rng_encaps", rngMutation,
            "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability", "encaps_rng_ignored"));
    } else {
        outcomes.push_back(PropertyPassed("kem", algorithm, propertyId, "encaps", "rng_encaps", rngMutation,
            "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_DIFFERENT"));
    }
    return outcomes;
}

std::vector<Outcome> EvaluateSIG(OQS_SIG *sig, const std::string& algorithm,
                                 const operation::OQS_SIG_SelfTest& op, size_t algorithmCount) {
    std::vector<Outcome> outcomes;
    size_t property = 0;
    if ( !SelectProperty(op.selector, algorithmCount, kSIGProperties, property) ) {
        outcomes.push_back(Diagnostic("sig", algorithm, "replay_selection", "selection", "ok", "not_run",
            "not_run", "unsupported_replay_property", "requested replay property is not a SIG property"));
        return outcomes;
    }
    const char *propertyId = kSIGProperties[property];
    const auto entropy = op.entropy.Get();
    const auto message = op.message.Get();

    std::vector<uint8_t> publicKey(sig->length_public_key);
    std::vector<uint8_t> secretKey(sig->length_secret_key);
    std::vector<uint8_t> signature(sig->length_signature);
    size_t signatureLen = 0;

    SetDeterministicRandom(entropy, op.selector, "sig-keypair");
    const OQS_STATUS keypairStatus = OQS_SIG_keypair(sig, DataOrDummy(publicKey), DataOrDummy(secretKey));
    if ( keypairStatus != OQS_SUCCESS ) {
        SetDeterministicRandom(entropy, op.selector, "sig-keypair");
        const OQS_STATUS controlled = OQS_SIG_keypair(sig, DataOrDummy(publicKey), DataOrDummy(secretKey));
        const auto system = CallWithSystemRandom([&]() {
            return OQS_SIG_keypair(sig, DataOrDummy(publicKey), DataOrDummy(secretKey));
        });
        outcomes.push_back(ControlledDiagnostic("sig", algorithm, "sig_roundtrip", "keypair",
            StatusName(keypairStatus), "keypair failed for a generated test case", controlled, system));
        return outcomes;
    }

    SetDeterministicRandom(entropy, op.selector, "sig-sign");
    const OQS_STATUS signStatus = OQS_SIG_sign(sig, DataOrDummy(signature), &signatureLen,
        DataOrDummy(message), message.size(), DataOrDummy(secretKey));
    if ( signStatus != OQS_SUCCESS || signatureLen > signature.size() ) {
        SetDeterministicRandom(entropy, op.selector, "sig-sign");
        size_t controlledLength = 0;
        const OQS_STATUS controlled = OQS_SIG_sign(sig, DataOrDummy(signature), &controlledLength,
            DataOrDummy(message), message.size(), DataOrDummy(secretKey));
        size_t defaultLength = 0;
        const auto system = CallWithSystemRandom([&]() {
            return OQS_SIG_sign(sig, DataOrDummy(signature), &defaultLength,
                DataOrDummy(message), message.size(), DataOrDummy(secretKey));
        });
        auto outcome = ControlledDiagnostic("sig", algorithm, "sig_roundtrip", "sign",
            signStatus == OQS_SUCCESS ? "invalid_output" : StatusName(signStatus),
            "sign failed for a generated key and message", controlled, system);
        if ( signStatus == OQS_SUCCESS && signatureLen > signature.size() ) {
            outcome.diagnosticClass = "invalid_signature_length";
        }
        outcomes.push_back(std::move(outcome));
        return outcomes;
    }

    const OQS_STATUS verifyStatus = OQS_SIG_verify(sig, DataOrDummy(message), message.size(),
        DataOrDummy(signature), signatureLen, DataOrDummy(publicKey));
    if ( verifyStatus != OQS_SUCCESS ) {
        outcomes.push_back(Finding("sig", algorithm, "sig_roundtrip", "verify", "roundtrip", {},
            "ok", StatusName(verifyStatus), "EXPECT_ACCEPTED", "OBSERVED_REJECTED", "functional",
            "functional_roundtrip_failure"));
        return outcomes;
    }

    if ( property == 0 ) {
        outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "verify", "roundtrip", {},
            "ok", "ok", "EXPECT_ACCEPTED", "OBSERVED_ACCEPTED"));
        return outcomes;
    }

    if ( property == 1 ) {
        auto mutatedSignature = signature;
        mutatedSignature.resize(signatureLen);
        const auto mutation = Mutate(mutatedSignature, op.mutation, op.selector);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("sig", algorithm, propertyId, "verify", "signature", mutation));
            return outcomes;
        }
        const OQS_STATUS status = OQS_SIG_verify(sig, DataOrDummy(message), message.size(),
            DataOrDummy(mutatedSignature), mutatedSignature.size(), DataOrDummy(publicKey));
        if ( status == OQS_SUCCESS ) {
            outcomes.push_back(Finding("sig", algorithm, propertyId, "verify", "signature", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability", "signature_malleability"));
        } else {
            outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "verify", "signature", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", "OBSERVED_REJECTED"));
        }
        return outcomes;
    }

    if ( property == 2 ) {
        auto mutatedMessage = message;
        const auto mutation = Mutate(mutatedMessage, op.mutation, op.selector + 1);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("sig", algorithm, propertyId, "verify", "message", mutation));
            return outcomes;
        }
        const OQS_STATUS status = OQS_SIG_verify(sig, DataOrDummy(mutatedMessage), mutatedMessage.size(),
            DataOrDummy(signature), signatureLen, DataOrDummy(publicKey));
        if ( status == OQS_SUCCESS ) {
            outcomes.push_back(Finding("sig", algorithm, propertyId, "verify", "message", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability", "message_binding_failure"));
        } else {
            outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "verify", "message", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", "OBSERVED_REJECTED"));
        }
        return outcomes;
    }

    if ( property == 3 ) {
        auto mutatedPublicKey = publicKey;
        const auto mutation = Mutate(mutatedPublicKey, op.mutation, op.selector + 2);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("sig", algorithm, propertyId, "verify", "public_key", mutation));
            return outcomes;
        }
        const OQS_STATUS status = OQS_SIG_verify(sig, DataOrDummy(message), message.size(),
            DataOrDummy(signature), signatureLen, DataOrDummy(mutatedPublicKey));
        if ( status == OQS_SUCCESS ) {
            auto finding = Finding("sig", algorithm, propertyId, "verify", "public_key", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability",
                "verification_key_malleability");
            /* Generic OQS_SIG has no public-key parser or serializer.  We
             * therefore do not pretend to prove canonicalization; a second
             * effective bit pattern at the exact byte tells us whether the
             * accepted byte is observably ignored by verification. */
            finding.canonicalizationStatus = "unsupported";
            auto probePublicKey = publicKey;
            const uint8_t originalDelta = publicKey[mutation.offset] ^ mutatedPublicKey[mutation.offset];
            const uint8_t probeDelta = originalDelta == 1 ? 2 : 1;
            const auto probe = MutateAt(probePublicKey, mutation.offset, probeDelta, "xor_probe");
            const OQS_STATUS probeStatus = probe.effective ?
                OQS_SIG_verify(sig, DataOrDummy(message), message.size(), DataOrDummy(signature),
                               signatureLen, DataOrDummy(probePublicKey)) : OQS_ERROR;
            finding.publicKeyProbeDeltaHex = probe.deltaHex;
            finding.publicKeyProbeStatus = StatusName(probeStatus);
            if ( probeStatus == OQS_SUCCESS ) {
                finding.findingSubclass = "ignored_public_key_bytes";
                finding.normalizedObservation = "ignored_public_key_bytes";
                finding.publicKeyByteUse = "not_observed_by_independent_probe";
            } else {
                finding.publicKeyByteUse = "observed_as_mutation_sensitive";
                finding.normalizedObservation = "verification_key_malleability";
            }
            outcomes.push_back(std::move(finding));
        } else {
            outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "verify", "public_key", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", "OBSERVED_REJECTED"));
        }
        return outcomes;
    }

    if ( property == 4 ) {
        auto mutatedSecretKey = secretKey;
        const auto mutation = Mutate(mutatedSecretKey, op.mutation, op.selector + 3);
        if ( !mutation.effective ) {
            outcomes.push_back(NoOpMutation("sig", algorithm, propertyId, "sign", "secret_key", mutation));
            return outcomes;
        }
        std::vector<uint8_t> alternateSignature(sig->length_signature);
        size_t alternateSignatureLen = 0;
        SetDeterministicRandom(entropy, op.selector, "sig-sign");
        const OQS_STATUS status = OQS_SIG_sign(sig, DataOrDummy(alternateSignature), &alternateSignatureLen,
            DataOrDummy(message), message.size(), DataOrDummy(mutatedSecretKey));
        const OQS_STATUS alternateVerify = status == OQS_SUCCESS && alternateSignatureLen <= alternateSignature.size() ?
            OQS_SIG_verify(sig, DataOrDummy(message), message.size(), DataOrDummy(alternateSignature),
                           alternateSignatureLen, DataOrDummy(publicKey)) : OQS_ERROR;
        if ( status == OQS_SUCCESS && alternateSignatureLen <= alternateSignature.size() &&
             alternateVerify == OQS_SUCCESS && alternateSignatureLen == signatureLen &&
             std::equal(alternateSignature.begin(), alternateSignature.begin() + alternateSignatureLen,
                        signature.begin()) ) {
            outcomes.push_back(Finding("sig", algorithm, propertyId, "sign", "secret_key", mutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability",
                "secret_key_ignored_or_malleable"));
        } else {
            const char *relation = status == OQS_SUCCESS && alternateVerify == OQS_SUCCESS ?
                "OBSERVED_DIFFERENT" : "OBSERVED_REJECTED";
            outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "sign", "secret_key", mutation,
                "ok", StatusName(status), "EXPECT_DIFFERENT", relation));
        }
        return outcomes;
    }

    if ( property == 5 ) {
        std::vector<uint8_t> alternatePublicKey(sig->length_public_key);
        std::vector<uint8_t> alternateSecretKey(sig->length_secret_key);
        SetDeterministicRandom(entropy, op.selector, "sig-keypair-rng-variant");
        const OQS_STATUS status = OQS_SIG_keypair(sig, DataOrDummy(alternatePublicKey),
            DataOrDummy(alternateSecretKey));
        const MutationResult rngMutation = RNGMutation(entropy, op.selector, "sig-keypair-rng-variant");
        if ( status != OQS_SUCCESS ) {
            SetDeterministicRandom(entropy, op.selector, "sig-keypair-rng-variant");
            const OQS_STATUS controlled = OQS_SIG_keypair(sig, DataOrDummy(alternatePublicKey),
                DataOrDummy(alternateSecretKey));
            const auto system = CallWithSystemRandom([&]() {
                return OQS_SIG_keypair(sig, DataOrDummy(alternatePublicKey), DataOrDummy(alternateSecretKey));
            });
            auto outcome = ControlledDiagnostic("sig", algorithm, propertyId, "keypair_rng_variant", "ok",
                "keypair failed with a distinct controlled RNG stream", controlled, system);
            outcome.mutationTarget = "rng_keypair";
            ApplyMutation(outcome, rngMutation);
            outcomes.push_back(std::move(outcome));
        } else if ( VectorsEqual(publicKey, alternatePublicKey) && VectorsEqual(secretKey, alternateSecretKey) ) {
            outcomes.push_back(Finding("sig", algorithm, propertyId, "keypair", "rng_keypair", rngMutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability", "keygen_rng_ignored"));
        } else {
            outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "keypair", "rng_keypair", rngMutation,
                "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_DIFFERENT"));
        }
        return outcomes;
    }

    std::vector<uint8_t> alternateSignature(sig->length_signature);
    size_t alternateSignatureLen = 0;
    SetDeterministicRandom(entropy, op.selector, "sig-sign-rng-variant");
    const OQS_STATUS status = OQS_SIG_sign(sig, DataOrDummy(alternateSignature), &alternateSignatureLen,
        DataOrDummy(message), message.size(), DataOrDummy(secretKey));
    const MutationResult rngMutation = RNGMutation(entropy, op.selector, "sig-sign-rng-variant");
    const OQS_STATUS alternateVerify = status == OQS_SUCCESS && alternateSignatureLen <= alternateSignature.size() ?
        OQS_SIG_verify(sig, DataOrDummy(message), message.size(), DataOrDummy(alternateSignature),
                       alternateSignatureLen, DataOrDummy(publicKey)) : OQS_ERROR;
    if ( status != OQS_SUCCESS || alternateSignatureLen > alternateSignature.size() ) {
        SetDeterministicRandom(entropy, op.selector, "sig-sign-rng-variant");
        size_t controlledLength = 0;
        const OQS_STATUS controlled = OQS_SIG_sign(sig, DataOrDummy(alternateSignature), &controlledLength,
            DataOrDummy(message), message.size(), DataOrDummy(secretKey));
        size_t defaultLength = 0;
        const auto system = CallWithSystemRandom([&]() {
            return OQS_SIG_sign(sig, DataOrDummy(alternateSignature), &defaultLength,
                DataOrDummy(message), message.size(), DataOrDummy(secretKey));
        });
        auto outcome = ControlledDiagnostic("sig", algorithm, propertyId, "sign_rng_variant", "ok",
            "sign failed with a distinct controlled RNG stream", controlled, system);
        outcome.mutationTarget = "rng_sign";
        ApplyMutation(outcome, rngMutation);
        outcomes.push_back(std::move(outcome));
    } else if ( alternateVerify == OQS_SUCCESS && alternateSignatureLen == signatureLen &&
                std::equal(alternateSignature.begin(), alternateSignature.begin() + alternateSignatureLen,
                           signature.begin()) ) {
        outcomes.push_back(Finding("sig", algorithm, propertyId, "sign", "rng_sign", rngMutation,
            "ok", "ok", "EXPECT_DIFFERENT", "OBSERVED_EQUAL", "malleability", "sign_rng_ignored"));
    } else {
        const char *relation = alternateVerify == OQS_SUCCESS ? "OBSERVED_DIFFERENT" : "OBSERVED_REJECTED";
        outcomes.push_back(PropertyPassed("sig", algorithm, propertyId, "sign", "rng_sign", rngMutation,
            "ok", StatusName(status), "EXPECT_DIFFERENT", relation));
    }
    return outcomes;
}

size_t RequiredReplayAttempts() {
    const char *configured = std::getenv(kReplayAttemptsEnv);
    if ( configured == nullptr || *configured == '\0' ) {
        return 3;
    }
    char *end = nullptr;
    const unsigned long value = std::strtoul(configured, &end, 10);
    return end != configured && *end == '\0' && value >= 3 && value <= 20 ?
        static_cast<size_t>(value) : 3;
}

struct ReplayReport {
    size_t attempts = 0;
    size_t reproduced = 0;
    std::string attemptResults = "[]";
};

template <typename Replay>
void PersistOutcomes(const std::vector<Outcome>& outcomes, const ReplayInput& input, Replay replay) {
    ReplayInput persistedInput = input;
    const bool hasSemanticCandidate = std::any_of(outcomes.begin(), outcomes.end(), [](const Outcome& outcome) {
        return outcome.kind == OutcomeKind::Finding;
    });
    if ( hasSemanticCandidate ) {
        const bool fixtureCaptured = CaptureCurrentRawFixture(persistedInput);
        if ( !fixtureCaptured ) {
            for (const auto& outcome : outcomes) {
                if ( outcome.kind != OutcomeKind::Finding ) {
                    continue;
                }
                Outcome diagnostic = outcome;
                diagnostic.kind = OutcomeKind::Diagnostic;
                diagnostic.classification = "operation_diagnostic";
                diagnostic.operationStatus = "operation_error";
                diagnostic.diagnosticClass = "replay_fixture_capture_failed";
                diagnostic.findingSubclass = "unreproduced";
                diagnostic.normalizedObservation = "unreproduced";
                diagnostic.replayResult = "unreproduced";
                diagnostic.diagnostic = "exact raw fuzzer input could not be captured or verified";
                WriteDiagnostic(diagnostic, persistedInput);
            }
            return;
        }
    }

    for (const auto& outcome : outcomes) {
        if ( outcome.kind == OutcomeKind::Passed || outcome.kind == OutcomeKind::Skipped ) {
            (void)WriteOutcome(outcome, persistedInput);
        } else if ( outcome.kind == OutcomeKind::Diagnostic ) {
            WriteDiagnostic(outcome, persistedInput);
        } else if ( outcome.kind == OutcomeKind::Finding ) {
            Outcome persisted = outcome;
            const ReplayReport report = replay(outcome);
            persisted.replayAttempts = report.attempts;
            persisted.replayReproduced = report.reproduced;
            persisted.replayAttemptResults = report.attemptResults;
            if ( report.attempts >= 3 && report.reproduced == report.attempts ) {
                persisted.replayResult = "reproduced";
                if ( WriteOutcome(persisted, persistedInput) ) {
                    std::printf("[liboqs] finding %s %s/%s: %s\n", persisted.primitive.c_str(),
                                persisted.algorithm.c_str(), persisted.propertyId.c_str(),
                                persisted.findingSubclass.c_str());
                }
            } else {
                persisted.kind = OutcomeKind::Diagnostic;
                persisted.classification = "operation_diagnostic";
                persisted.operationStatus = "operation_error";
                persisted.diagnosticClass = "unreproduced";
                persisted.findingSubclass = "unreproduced";
                persisted.normalizedObservation = "unreproduced";
                persisted.mutatedStatus = "unreproduced";
                persisted.replayResult = "unreproduced";
                persisted.diagnostic = "semantic candidate did not reproduce on every exact-input replay";
                WriteDiagnostic(persisted, persistedInput);
            }
        }
    }
}

} /* namespace */

liboqs::liboqs(void) :
    Module("liboqs")
{
    const int kemCount = OQS_KEM_alg_count();
    for (int i = 0; i < kemCount; i++) {
        const char *name = OQS_KEM_alg_identifier(static_cast<size_t>(i));
        if ( name == nullptr ) {
            std::printf("[liboqs] skipped KEM algorithm at index %d: missing identifier\n", i);
            continue;
        }
        if ( OQS_KEM_alg_is_enabled(name) != 1 ) {
            std::printf("[liboqs] skipped KEM algorithm: %s (disabled)\n", name);
            continue;
        }

        std::unique_ptr<OQS_KEM, KEMDeleter> kem(OQS_KEM_new(name));
        if ( kem != nullptr ) {
            kemAlgorithms.emplace_back(name);
        } else {
            std::printf("[liboqs] skipped KEM algorithm: %s (OQS_KEM_new failed)\n", name);
        }
    }

    const int sigCount = OQS_SIG_alg_count();
    for (int i = 0; i < sigCount; i++) {
        const char *name = OQS_SIG_alg_identifier(static_cast<size_t>(i));
        if ( name == nullptr ) {
            std::printf("[liboqs] skipped SIG algorithm at index %d: missing identifier\n", i);
            continue;
        }
        if ( OQS_SIG_alg_is_enabled(name) != 1 ) {
            std::printf("[liboqs] skipped SIG algorithm: %s (disabled)\n", name);
            continue;
        }

        std::unique_ptr<OQS_SIG, SIGDeleter> sig(OQS_SIG_new(name));
        if ( sig != nullptr ) {
            sigAlgorithms.emplace_back(name);
        } else {
            std::printf("[liboqs] skipped SIG algorithm: %s (OQS_SIG_new failed)\n", name);
        }
    }

    std::printf("[liboqs] enabled KEM algorithms: %zu\n", kemAlgorithms.size());
    std::printf("[liboqs] enabled SIG algorithms: %zu\n", sigAlgorithms.size());
    WriteMetadata(kemAlgorithms, sigAlgorithms);
}

std::optional<bool> liboqs::OpOQSKEMSelfTest(operation::OQS_KEM_SelfTest& op) {
    const auto input = ReplayData(op);
    if ( kemAlgorithms.empty() ) {
        auto skipped = NewOutcome(OutcomeKind::Skipped, "kem", "", "kem_unavailable", "selection", "none");
        skipped.setupStatus = "unsupported";
        skipped.diagnosticClass = "unsupported_algorithm";
        skipped.diagnostic = "no enabled KEM algorithms are available";
        (void)WriteOutcome(skipped, input);
        return true;
    }

    std::string algorithm;
    if ( !SelectAlgorithm(kemAlgorithms, op.selector, algorithm) ) {
        const char *requested = ReplayOverride(kReplayAlgorithmEnv);
        WriteDiagnostic(Diagnostic("kem", requested != nullptr ? requested : "unknown", "replay_selection",
            "selection", "unsupported", "not_run", "not_run", "unsupported_replay_algorithm",
            "requested replay algorithm is not enabled"), input);
        return true;
    }
    std::unique_ptr<OQS_KEM, KEMDeleter> kem(OQS_KEM_new(algorithm.c_str()));
    if ( kem == nullptr ) {
        WriteDiagnostic(Diagnostic("kem", algorithm, "kem_roundtrip", "new", "unsupported",
            "unsupported", "not_run", "unsupported_algorithm", "OQS_KEM_new failed"), input);
        return true;
    }

    const auto outcomes = EvaluateKEM(kem.get(), algorithm, op, kemAlgorithms.size());
    PersistOutcomes(outcomes, input, [&](const Outcome& finding) {
        ReplayReport report;
        const size_t attempts = RequiredReplayAttempts();
        report.attemptResults = "[";
        for (size_t attempt = 0; attempt < attempts; attempt++) {
            std::unique_ptr<OQS_KEM, KEMDeleter> replayKem(OQS_KEM_new(algorithm.c_str()));
            bool reproduced = false;
            if ( replayKem != nullptr ) {
                const auto replay = EvaluateKEM(replayKem.get(), algorithm, op, kemAlgorithms.size());
                reproduced = std::any_of(replay.begin(), replay.end(), [&](const Outcome& candidate) {
                    return IsSameFinding(finding, candidate);
                });
            }
            if ( attempt != 0 ) {
                report.attemptResults += ", ";
            }
            report.attemptResults += reproduced ? "\"reproduced\"" : "\"unreproduced\"";
            report.attempts++;
            if ( reproduced ) {
                report.reproduced++;
            }
        }
        report.attemptResults += "]";
        return report;
    });
    /* The legacy Module ABI has only optional<bool>.  Findings and recoverable
     * liboqs return codes are fully represented in the sidecar Outcome above;
     * true deliberately lets libFuzzer continue its healthy campaign. */
    return true;
}

std::optional<bool> liboqs::OpOQSSIGSelfTest(operation::OQS_SIG_SelfTest& op) {
    const auto input = ReplayData(op);
    if ( sigAlgorithms.empty() ) {
        auto skipped = NewOutcome(OutcomeKind::Skipped, "sig", "", "sig_unavailable", "selection", "none");
        skipped.setupStatus = "unsupported";
        skipped.diagnosticClass = "unsupported_algorithm";
        skipped.diagnostic = "no enabled SIG algorithms are available";
        (void)WriteOutcome(skipped, input);
        return true;
    }

    std::string algorithm;
    if ( !SelectAlgorithm(sigAlgorithms, op.selector, algorithm) ) {
        const char *requested = ReplayOverride(kReplayAlgorithmEnv);
        WriteDiagnostic(Diagnostic("sig", requested != nullptr ? requested : "unknown", "replay_selection",
            "selection", "unsupported", "not_run", "not_run", "unsupported_replay_algorithm",
            "requested replay algorithm is not enabled"), input);
        return true;
    }
    std::unique_ptr<OQS_SIG, SIGDeleter> sig(OQS_SIG_new(algorithm.c_str()));
    if ( sig == nullptr ) {
        WriteDiagnostic(Diagnostic("sig", algorithm, "sig_roundtrip", "new", "unsupported",
            "unsupported", "not_run", "unsupported_algorithm", "OQS_SIG_new failed"), input);
        return true;
    }

    const auto outcomes = EvaluateSIG(sig.get(), algorithm, op, sigAlgorithms.size());
    PersistOutcomes(outcomes, input, [&](const Outcome& finding) {
        ReplayReport report;
        const size_t attempts = RequiredReplayAttempts();
        report.attemptResults = "[";
        for (size_t attempt = 0; attempt < attempts; attempt++) {
            std::unique_ptr<OQS_SIG, SIGDeleter> replaySig(OQS_SIG_new(algorithm.c_str()));
            bool reproduced = false;
            if ( replaySig != nullptr ) {
                const auto replay = EvaluateSIG(replaySig.get(), algorithm, op, sigAlgorithms.size());
                reproduced = std::any_of(replay.begin(), replay.end(), [&](const Outcome& candidate) {
                    return IsSameFinding(finding, candidate);
                });
            }
            if ( attempt != 0 ) {
                report.attemptResults += ", ";
            }
            report.attemptResults += reproduced ? "\"reproduced\"" : "\"unreproduced\"";
            report.attempts++;
            if ( reproduced ) {
                report.reproduced++;
            }
        }
        report.attemptResults += "]";
        return report;
    });
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
