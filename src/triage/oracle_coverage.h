#ifndef PQCFUZZ_TRIAGE_ORACLE_COVERAGE_H
#define PQCFUZZ_TRIAGE_ORACLE_COVERAGE_H

#include <string>

#include "oracles/oracle_executor.h"

namespace pqcfuzz {

void RecordEnvelopeParseRejected(const std::string &result_dir);
void RecordEnvelopeParsed(const std::string &result_dir);
void RecordAlgorithmRejected(const std::string &result_dir);
void RecordRoutingRejected(const std::string &result_dir);
void RecordOracleTrace(const std::string &result_dir, const KEMOracleTrace &trace);

}  // namespace pqcfuzz

#endif
