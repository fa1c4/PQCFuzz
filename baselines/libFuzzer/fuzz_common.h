#ifndef PQCDF_LIBFUZZER_FUZZ_COMMON_H
#define PQCDF_LIBFUZZER_FUZZ_COMMON_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

/*
 * This file intentionally does not use PQCFuzz runtime code.  The libFuzzer
 * baseline owns its small envelope, normalisation, and finding format so that
 * it remains an independently reproducible baseline.
 *
 * Semantic envelope, version 1 (all multibyte fields are little endian):
 *
 *   0       format_version (1)
 *   1       primitive (1 = KEM, 2 = SIG)
 *   2       property_id (see property enums below)
 *   3       mutation_mode (0 = XOR, 1 = SET, 2 = noncanonical XOR)
 *   4..7    algorithm_index
 *   8..15   deterministic RNG seed
 *   16..17  RNG tape length
 *   18..19  message length
 *   20..23  mutation offset
 *   24      mutation mask/value (zero deliberately means ineffective)
 *   25      mutation width
 *   26..27  reserved (zero)
 *   28..    RNG tape, followed by message bytes
 *
 * An invalid envelope is deliberately ignored.  This gives the semantic
 * profile a stable, property-addressable input format without turning parser
 * mistakes into findings or crashes.
 */

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PQCDF_ENVELOPE_VERSION 1u
#define PQCDF_ENVELOPE_HEADER_SIZE 28u
#define PQCDF_PRIMITIVE_KEM 1u
#define PQCDF_PRIMITIVE_SIG 2u

#define PQCDF_MUTATION_XOR 0u
#define PQCDF_MUTATION_SET 1u
#define PQCDF_MUTATION_NONCANONICAL_XOR 2u

#define PQCDF_MAX_MESSAGE_LEN 4096u

/* Property identifiers match the IDs used in the baseline finding records. */
enum pqcdf_kem_property {
	PQCDF_KEM_PROPERTY_ROUNDTRIP = 1,
	PQCDF_KEM_PROPERTY_DECAPS_C = 2,
	PQCDF_KEM_PROPERTY_DECAPS_SK = 3,
	PQCDF_KEM_PROPERTY_ENCAPS_PK = 4,
	PQCDF_KEM_PROPERTY_KEYGEN_BADRNG = 5,
	PQCDF_KEM_PROPERTY_ENCAPS_BADRNG = 6,
};

enum pqcdf_sig_property {
	PQCDF_SIG_PROPERTY_ROUNDTRIP = 1,
	PQCDF_SIG_PROPERTY_VERIFY_SIG = 2,
	PQCDF_SIG_PROPERTY_VERIFY_M = 3,
	PQCDF_SIG_PROPERTY_VERIFY_PK = 4,
	PQCDF_SIG_PROPERTY_SIGN_SK = 5,
	PQCDF_SIG_PROPERTY_KEYGEN_BADRNG = 6,
	PQCDF_SIG_PROPERTY_SIGN_BADRNG = 7,
};

typedef enum pqcdf_outcome {
	PQCDF_OUTCOME_OK = 0,
	PQCDF_OUTCOME_REJECTED,
	PQCDF_OUTCOME_OPERATION_ERROR,
	PQCDF_OUTCOME_UNSUPPORTED,
	PQCDF_OUTCOME_INVARIANT_VIOLATION,
	PQCDF_OUTCOME_PROCESS_CRASH,
	PQCDF_OUTCOME_PROCESS_HANG,
} pqcdf_outcome;

typedef struct pqcdf_envelope {
	uint8_t format_version;
	uint8_t primitive;
	uint8_t property_id;
	uint8_t mutation_mode;
	uint32_t algorithm_index;
	uint64_t rng_seed;
	uint16_t rng_tape_len;
	uint16_t message_len;
	uint32_t mutation_offset;
	uint8_t mutation_mask;
	uint8_t mutation_width;
	const uint8_t *rng_tape;
	const uint8_t *message;
	const uint8_t *raw;
	size_t raw_size;
} pqcdf_envelope;

typedef const char *(*pqcdf_algorithm_name_fn)(size_t index);

static const uint8_t *pqcdf_rng_data = NULL;
static size_t pqcdf_rng_size = 0;
static size_t pqcdf_rng_cursor = 0;
static uint64_t pqcdf_rng_state = 0x9e3779b97f4a7c15ULL;
static uint8_t pqcdf_rng_tape_xor = 0;

static size_t pqcdf_min_size(size_t a, size_t b) {
	return a < b ? a : b;
}

static uint16_t pqcdf_read_u16(const uint8_t *data, size_t size, size_t offset) {
	uint16_t value = 0;
	for (size_t i = 0; i < 2; i++) {
		if (data != NULL && offset + i < size) {
			value |= ((uint16_t)data[offset + i]) << (8u * (unsigned)i);
		}
	}
	return value;
}

static uint32_t pqcdf_read_u32(const uint8_t *data, size_t size, size_t offset) {
	uint32_t value = 0;
	for (size_t i = 0; i < 4; i++) {
		if (data != NULL && offset + i < size) {
			value |= ((uint32_t)data[offset + i]) << (8u * (unsigned)i);
		}
	}
	return value;
}

static uint64_t pqcdf_read_u64(const uint8_t *data, size_t size, size_t offset) {
	uint64_t value = 0;
	for (size_t i = 0; i < 8; i++) {
		if (data != NULL && offset + i < size) {
			value |= ((uint64_t)data[offset + i]) << (8u * (unsigned)i);
		}
	}
	return value;
}

static int pqcdf_parse_envelope(const uint8_t *data, size_t size, pqcdf_envelope *out) {
	if (out == NULL || data == NULL || size < PQCDF_ENVELOPE_HEADER_SIZE) {
		return 0;
	}
	if (data[0] != PQCDF_ENVELOPE_VERSION ||
		(data[1] != PQCDF_PRIMITIVE_KEM && data[1] != PQCDF_PRIMITIVE_SIG) ||
		data[26] != 0 || data[27] != 0) {
		return 0;
	}

	const uint16_t rng_tape_len = pqcdf_read_u16(data, size, 16);
	const uint16_t message_len = pqcdf_read_u16(data, size, 18);
	if (message_len > PQCDF_MAX_MESSAGE_LEN ||
		rng_tape_len > size - PQCDF_ENVELOPE_HEADER_SIZE) {
		return 0;
	}
	const size_t payload_size = size - PQCDF_ENVELOPE_HEADER_SIZE;
	if ((size_t)rng_tape_len + (size_t)message_len != payload_size) {
		return 0;
	}

	out->format_version = data[0];
	out->primitive = data[1];
	out->property_id = data[2];
	out->mutation_mode = data[3];
	out->algorithm_index = pqcdf_read_u32(data, size, 4);
	out->rng_seed = pqcdf_read_u64(data, size, 8);
	out->rng_tape_len = rng_tape_len;
	out->message_len = message_len;
	out->mutation_offset = pqcdf_read_u32(data, size, 20);
	out->mutation_mask = data[24];
	out->mutation_width = data[25];
	out->rng_tape = data + PQCDF_ENVELOPE_HEADER_SIZE;
	out->message = out->rng_tape + rng_tape_len;
	out->raw = data;
	out->raw_size = size;
	return 1;
}

static uint64_t pqcdf_next_u64(void) {
	uint64_t x = pqcdf_rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	pqcdf_rng_state = x;
	return x * 0x2545f4914f6cdd1dULL;
}

static void pqcdf_seed_rng_variant(const uint8_t *data, size_t size, uint64_t seed, uint8_t variant) {
	pqcdf_rng_data = data;
	pqcdf_rng_size = size;
	pqcdf_rng_cursor = 0;
	pqcdf_rng_tape_xor = variant == 0 ? 0 : 0xa5u;
	pqcdf_rng_state = seed ^ 0x9e3779b97f4a7c15ULL ^
		(variant == 0 ? 0 : 0xd1b54a32d192ed03ULL);
	if (pqcdf_rng_state == 0) {
		pqcdf_rng_state = 0xd1b54a32d192ed03ULL;
	}
}

static void pqcdf_seed_envelope_rng(const pqcdf_envelope *envelope, uint8_t variant) {
	pqcdf_seed_rng_variant(envelope->rng_tape, envelope->rng_tape_len,
		envelope->rng_seed, variant);
}

static void pqcdf_randombytes(uint8_t *random_array, size_t bytes_to_read) {
	for (size_t i = 0; i < bytes_to_read; i++) {
		uint8_t value = (uint8_t)(pqcdf_next_u64() >> 56);
		if (pqcdf_rng_data != NULL && pqcdf_rng_cursor < pqcdf_rng_size) {
			value ^= (uint8_t)(pqcdf_rng_data[pqcdf_rng_cursor++] ^ pqcdf_rng_tape_xor);
		}
		random_array[i] = value;
	}
}

static void *pqcdf_alloc(size_t size) {
	return calloc(size == 0 ? 1 : size, 1);
}

static void pqcdf_secure_free(void *ptr, size_t size) {
	if (ptr != NULL) {
		volatile uint8_t *p = (volatile uint8_t *)ptr;
		for (size_t i = 0; i < size; i++) {
			p[i] = 0;
		}
		free(ptr);
	}
}

static const char *pqcdf_outcome_name(pqcdf_outcome outcome) {
	switch (outcome) {
	case PQCDF_OUTCOME_OK:
		return "ok";
	case PQCDF_OUTCOME_REJECTED:
		return "rejected";
	case PQCDF_OUTCOME_OPERATION_ERROR:
		return "operation_error";
	case PQCDF_OUTCOME_UNSUPPORTED:
		return "unsupported";
	case PQCDF_OUTCOME_INVARIANT_VIOLATION:
		return "invariant_violation";
	case PQCDF_OUTCOME_PROCESS_CRASH:
		return "process_crash";
	case PQCDF_OUTCOME_PROCESS_HANG:
		return "process_hang";
	}
	return "operation_error";
}

static int pqcdf_is_semantic_profile(void) {
	const char *profile = getenv("PQCDF_LIBFUZZER_PROFILE");
	return profile != NULL && strcmp(profile, "semantic") == 0;
}

static int pqcdf_is_noncanonical_mutation(const pqcdf_envelope *envelope) {
	return envelope->mutation_mode == PQCDF_MUTATION_NONCANONICAL_XOR;
}

static int pqcdf_ascii_tolower(int c) {
	return tolower((unsigned char)c);
}

static int pqcdf_contains_insensitive(const char *haystack, const char *needle) {
	if (haystack == NULL || needle == NULL) {
		return 0;
	}
	if (*needle == '\0') {
		return 1;
	}
	for (const char *h = haystack; *h != '\0'; ++h) {
		const char *hh = h;
		const char *nn = needle;
		while (*nn != '\0' && *hh != '\0' &&
			pqcdf_ascii_tolower((unsigned char)*hh) == pqcdf_ascii_tolower((unsigned char)*nn)) {
			++hh;
			++nn;
		}
		if (*nn == '\0') {
			return 1;
		}
	}
	return 0;
}

static int pqcdf_is_classic_mceliece_algorithm(const char *algorithm) {
	return pqcdf_contains_insensitive(algorithm, "Classic-McEliece") ||
		pqcdf_contains_insensitive(algorithm, "Classic McEliece") ||
		pqcdf_contains_insensitive(algorithm, "McEliece") ||
		pqcdf_contains_insensitive(algorithm, "mceliece");
}

static int pqcdf_is_threebears_algorithm(const char *algorithm) {
	return pqcdf_contains_insensitive(algorithm, "ThreeBears") ||
		pqcdf_contains_insensitive(algorithm, "BabyBear") ||
		pqcdf_contains_insensitive(algorithm, "MamaBear") ||
		pqcdf_contains_insensitive(algorithm, "PapaBear");
}

static int pqcdf_is_sparse_pk_single_challenge_kem(const char *algorithm) {
	return pqcdf_is_classic_mceliece_algorithm(algorithm) ||
		pqcdf_is_threebears_algorithm(algorithm);
}

static int pqcdf_is_deterministic_signature_no_external_sign_rng(const char *algorithm) {
	return pqcdf_contains_insensitive(algorithm, "MQDSS") ||
		pqcdf_contains_insensitive(algorithm, "Picnic") ||
		pqcdf_contains_insensitive(algorithm, "Rainbow");
}

static int pqcdf_is_falcon_norm_bound_verify_pk(const char *algorithm) {
	return pqcdf_contains_insensitive(algorithm, "Falcon");
}

static int pqcdf_mutate_copy(uint8_t *destination, const uint8_t *source, size_t size,
	const pqcdf_envelope *envelope) {
	if (destination == NULL || source == NULL || envelope == NULL || size == 0 ||
		envelope->mutation_width == 0 || envelope->mutation_mask == 0 ||
		envelope->mutation_offset >= size ||
		(envelope->mutation_mode != PQCDF_MUTATION_XOR &&
		 envelope->mutation_mode != PQCDF_MUTATION_SET &&
		 envelope->mutation_mode != PQCDF_MUTATION_NONCANONICAL_XOR)) {
		return 0;
	}
	memcpy(destination, source, size);
	const size_t width = pqcdf_min_size(envelope->mutation_width,
		size - (size_t)envelope->mutation_offset);
	for (size_t i = 0; i < width; ++i) {
		const size_t index = (size_t)envelope->mutation_offset + i;
		if (envelope->mutation_mode == PQCDF_MUTATION_SET) {
			destination[index] = (uint8_t)(envelope->mutation_mask + (uint8_t)i);
		} else {
			destination[index] ^= (uint8_t)(envelope->mutation_mask + (uint8_t)i);
		}
	}
	return memcmp(destination, source, size) != 0;
}

static uint64_t pqcdf_fnv1a(const uint8_t *data, size_t size, uint64_t state) {
	for (size_t i = 0; i < size; ++i) {
		state ^= data[i];
		state *= 1099511628211ULL;
	}
	return state;
}

static void pqcdf_digest_hex(const uint8_t *data, size_t size, char output[33]) {
	uint64_t left = pqcdf_fnv1a(data, size, 1469598103934665603ULL);
	uint64_t right = pqcdf_fnv1a(data, size, 1099511628211ULL ^ (uint64_t)size);
	right = pqcdf_fnv1a((const uint8_t *)&left, sizeof(left), right);
	(void)snprintf(output, 33, "%016llx%016llx", (unsigned long long)left,
		(unsigned long long)right);
}

static void pqcdf_json_string(FILE *file, const char *value) {
	if (value == NULL) {
		fputs("null", file);
		return;
	}
	fputc('"', file);
	for (const unsigned char *p = (const unsigned char *)value; *p != 0; ++p) {
		switch (*p) {
		case '"':
			fputs("\\\"", file);
			break;
		case '\\':
			fputs("\\\\", file);
			break;
		case '\b':
			fputs("\\b", file);
			break;
		case '\f':
			fputs("\\f", file);
			break;
		case '\n':
			fputs("\\n", file);
			break;
		case '\r':
			fputs("\\r", file);
			break;
		case '\t':
			fputs("\\t", file);
			break;
		default:
			if (*p < 0x20u) {
				fprintf(file, "\\u%04x", (unsigned)*p);
			} else {
				fputc(*p, file);
			}
			break;
		}
	}
	fputc('"', file);
}

static int pqcdf_make_directories(const char *directory) {
	if (directory == NULL || *directory == '\0') {
		return 0;
	}
	char path[PATH_MAX];
	const size_t length = strlen(directory);
	if (length >= sizeof(path)) {
		return 0;
	}
	memcpy(path, directory, length + 1);
	for (char *cursor = path + 1; *cursor != '\0'; ++cursor) {
		if (*cursor != '/') {
			continue;
		}
		*cursor = '\0';
		if (*path != '\0' && mkdir(path, 0700) != 0 && errno != EEXIST) {
			return 0;
		}
		*cursor = '/';
	}
	return mkdir(path, 0700) == 0 || errno == EEXIST;
}

static int pqcdf_write_all(int fd, const uint8_t *data, size_t size) {
	while (size > 0) {
		const ssize_t result = write(fd, data, size);
		if (result <= 0) {
			return 0;
		}
		data += (size_t)result;
		size -= (size_t)result;
	}
	return 1;
}

static int pqcdf_write_input_if_absent(const char *path, const uint8_t *data, size_t size) {
	const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		return errno == EEXIST ? 1 : 0;
	}
	const int ok = pqcdf_write_all(fd, data, size);
	if (close(fd) != 0 || !ok) {
		(void)unlink(path);
		return 0;
	}
	return 1;
}

static int pqcdf_open_unique_json(const char *path, FILE **file_out) {
	const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		return 0;
	}
	FILE *file = fdopen(fd, "w");
	if (file == NULL) {
		(void)close(fd);
		(void)unlink(path);
		return 0;
	}
	*file_out = file;
	return 1;
}

static unsigned long pqcdf_max_exemplars_per_group(void) {
	const char *configured = getenv("PQCDF_LIBFUZZER_MAX_EXEMPLARS_PER_GROUP");
	if (configured == NULL || *configured == '\0') {
		return 3;
	}
	char *end = NULL;
	const unsigned long value = strtoul(configured, &end, 10);
	if (end == configured || *end != '\0' || value == 0 || value > 1000) {
		return 3;
	}
	return value;
}

static unsigned long pqcdf_count_group_exemplars(const char *directory, const char *group_digest) {
	DIR *handle = opendir(directory);
	if (handle == NULL) {
		return 0;
	}
	const size_t prefix_length = strlen(group_digest) + 1;
	unsigned long count = 0;
	for (struct dirent *entry = readdir(handle); entry != NULL; entry = readdir(handle)) {
		const size_t name_length = strlen(entry->d_name);
		if (name_length > prefix_length + 5 &&
			strncmp(entry->d_name, group_digest, prefix_length - 1) == 0 &&
			entry->d_name[prefix_length - 1] == '-' &&
			strcmp(entry->d_name + name_length - 5, ".json") == 0) {
			++count;
		}
	}
	(void)closedir(handle);
	return count;
}

static int pqcdf_acquire_group_lock(const char *directory, const char *group_digest,
	char lock_path[PATH_MAX]) {
	if (snprintf(lock_path, PATH_MAX, "%s/.%s.lock", directory, group_digest) >= PATH_MAX) {
		return 0;
	}
	const int fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		return 0;
	}
	(void)close(fd);
	return 1;
}

static void pqcdf_record_finding(const char *primitive, const char *algorithm,
	const char *property_id, const char *expected_relation, const char *finding_class,
	const char *finding_subclass, const char *baseline_status, const char *mutated_status,
	int baseline_accepted, int mutated_accepted, const char *normalized_observation,
	const uint8_t *input, size_t input_size) {
	if (!pqcdf_is_semantic_profile()) {
		return;
	}
	const char *directory = getenv("PQCDF_LIBFUZZER_FINDINGS_DIR");
	if (directory == NULL || !pqcdf_make_directories(directory)) {
		return;
	}

	char group_source[1024];
	const int group_length = snprintf(group_source, sizeof(group_source), "%s|%s|%s|%s",
		algorithm, property_id, finding_class, normalized_observation);
	if (group_length < 0 || group_length >= (int)sizeof(group_source)) {
		return;
	}
	char group_digest[33];
	char input_digest[33];
	pqcdf_digest_hex((const uint8_t *)group_source, (size_t)group_length, group_digest);
	pqcdf_digest_hex(input, input_size, input_digest);

	char lock_path[PATH_MAX];
	if (!pqcdf_acquire_group_lock(directory, group_digest, lock_path)) {
		return;
	}
	const unsigned long count = pqcdf_count_group_exemplars(directory, group_digest);
	if (count >= pqcdf_max_exemplars_per_group()) {
		(void)unlink(lock_path);
		return;
	}

	char input_name[80];
	char finding_name[80];
	(void)snprintf(input_name, sizeof(input_name), "%s-%s.input", group_digest, input_digest);
	(void)snprintf(finding_name, sizeof(finding_name), "%s-%s.json", group_digest, input_digest);
	char input_path[PATH_MAX];
	char finding_path[PATH_MAX];
	if (snprintf(input_path, sizeof(input_path), "%s/%s", directory, input_name) >= (int)sizeof(input_path) ||
		snprintf(finding_path, sizeof(finding_path), "%s/%s", directory, finding_name) >= (int)sizeof(finding_path) ||
		!pqcdf_write_input_if_absent(input_path, input, input_size)) {
		(void)unlink(lock_path);
		return;
	}

	FILE *file = NULL;
	if (!pqcdf_open_unique_json(finding_path, &file)) {
		(void)unlink(lock_path);
		return;
	}
	fputs("{\n  \"format_version\": 1,\n  \"baseline\": \"libFuzzer\",\n  \"primitive\": ", file);
	pqcdf_json_string(file, primitive);
	fputs(",\n  \"algorithm\": ", file);
	pqcdf_json_string(file, algorithm);
	fputs(",\n  \"property_id\": ", file);
	pqcdf_json_string(file, property_id);
	fputs(",\n  \"expected_relation\": ", file);
	pqcdf_json_string(file, expected_relation);
	fputs(",\n  \"finding_class\": ", file);
	pqcdf_json_string(file, finding_class);
	fputs(",\n  \"finding_subclass\": ", file);
	pqcdf_json_string(file, finding_subclass);
	fputs(",\n  \"normalized_observation\": ", file);
	pqcdf_json_string(file, normalized_observation);
	fputs(",\n  \"baseline_status\": ", file);
	pqcdf_json_string(file, baseline_status);
	fputs(",\n  \"mutated_status\": ", file);
	pqcdf_json_string(file, mutated_status);
	fprintf(file, ",\n  \"baseline_accepted\": %s,\n  \"mutated_accepted\": %s",
		baseline_accepted ? "true" : "false", mutated_accepted ? "true" : "false");
	fputs(",\n  \"input_digest\": ", file);
	pqcdf_json_string(file, input_digest);
	fputs(",\n  \"input_file\": ", file);
	pqcdf_json_string(file, input_name);
	fputs(",\n  \"outcome\": \"invariant_violation\"\n}\n", file);
	if (fclose(file) != 0) {
		(void)unlink(finding_path);
	}
	(void)unlink(lock_path);
}

static void pqcdf_record_operation_diagnostic(const char *primitive, const char *algorithm,
	const char *operation, const char *deterministic_status, const char *default_status,
	const uint8_t *input, size_t input_size) {
	const char *directory = getenv("PQCDF_LIBFUZZER_DIAGNOSTICS_DIR");
	if (directory == NULL || !pqcdf_make_directories(directory)) {
		return;
	}
	char input_digest[33];
	pqcdf_digest_hex(input, input_size, input_digest);
	char name[96];
	(void)snprintf(name, sizeof(name), "diagnostic-%s-%s.json", operation, input_digest);
	char path[PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path)) {
		return;
	}
	FILE *file = NULL;
	if (!pqcdf_open_unique_json(path, &file)) {
		return;
	}
	fputs("{\n  \"format_version\": 1,\n  \"classification\": \"harness_rng_diagnostic\",\n  \"outcome\": ", file);
	pqcdf_json_string(file, deterministic_status);
	fputs(",\n  \"primitive\": ", file);
	pqcdf_json_string(file, primitive);
	fputs(",\n  \"algorithm\": ", file);
	pqcdf_json_string(file, algorithm);
	fputs(",\n  \"operation\": ", file);
	pqcdf_json_string(file, operation);
	fputs(",\n  \"deterministic_rng_mode\": true,\n  \"deterministic_status\": ", file);
	pqcdf_json_string(file, deterministic_status);
	fputs(",\n  \"default_rng_status\": ", file);
	pqcdf_json_string(file, default_status);
	fputs(",\n  \"input_digest\": ", file);
	pqcdf_json_string(file, input_digest);
	fputs("\n}\n", file);
	(void)fclose(file);
}

static void pqcdf_record_property_outcome(const char *primitive, const char *algorithm,
	const char *property_id, const char *classification, const uint8_t *input,
	size_t input_size) {
	if (!pqcdf_is_semantic_profile()) {
		return;
	}
	const char *directory = getenv("PQCDF_LIBFUZZER_OUTCOMES_DIR");
	if (directory == NULL || !pqcdf_make_directories(directory)) {
		return;
	}
	char group_source[1024];
	const int group_length = snprintf(group_source, sizeof(group_source), "%s|%s|%s|%s",
		primitive, algorithm, property_id, classification);
	if (group_length < 0 || group_length >= (int)sizeof(group_source)) {
		return;
	}
	char group_digest[33];
	char input_digest[33];
	pqcdf_digest_hex((const uint8_t *)group_source, (size_t)group_length, group_digest);
	pqcdf_digest_hex(input, input_size, input_digest);
	char path[PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/%s.json", directory, group_digest) >= (int)sizeof(path)) {
		return;
	}
	FILE *file = NULL;
	if (!pqcdf_open_unique_json(path, &file)) {
		return;
	}
	fputs("{\n  \"format_version\": 1,\n  \"baseline\": \"libFuzzer\",\n  \"classification\": ", file);
	pqcdf_json_string(file, classification);
	fputs(",\n  \"primitive\": ", file);
	pqcdf_json_string(file, primitive);
	fputs(",\n  \"algorithm\": ", file);
	pqcdf_json_string(file, algorithm);
	fputs(",\n  \"property_id\": ", file);
	pqcdf_json_string(file, property_id);
	fputs(",\n  \"input_digest\": ", file);
	pqcdf_json_string(file, input_digest);
	fputs("\n}\n", file);
	if (fclose(file) != 0) {
		(void)unlink(path);
	}
}

static void pqcdf_record_oracle_assumption_outcome(const char *primitive,
	const char *algorithm, const char *property_id, const char *classification,
	const char *reason, const pqcdf_envelope *envelope) {
	if (!pqcdf_is_semantic_profile()) {
		return;
	}
	const char *directory = getenv("PQCDF_LIBFUZZER_OUTCOMES_DIR");
	if (directory == NULL || !pqcdf_make_directories(directory)) {
		return;
	}
	char group_source[1024];
	const int group_length = snprintf(group_source, sizeof(group_source), "%s|%s|%s|%s",
		primitive, algorithm, property_id, classification);
	if (group_length < 0 || group_length >= (int)sizeof(group_source)) {
		return;
	}
	char group_digest[33];
	char input_digest[33];
	pqcdf_digest_hex((const uint8_t *)group_source, (size_t)group_length, group_digest);
	pqcdf_digest_hex(envelope->raw, envelope->raw_size, input_digest);
	char path[PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/%s.json", directory, group_digest) >= (int)sizeof(path)) {
		return;
	}
	FILE *file = NULL;
	if (!pqcdf_open_unique_json(path, &file)) {
		return;
	}
	fputs("{\n  \"format_version\": 1,\n  \"baseline\": \"libFuzzer\",\n  \"classification\": ", file);
	pqcdf_json_string(file, classification);
	fputs(",\n  \"reason\": ", file);
	pqcdf_json_string(file, reason);
	fputs(",\n  \"primitive\": ", file);
	pqcdf_json_string(file, primitive);
	fputs(",\n  \"algorithm\": ", file);
	pqcdf_json_string(file, algorithm);
	fputs(",\n  \"property_id\": ", file);
	pqcdf_json_string(file, property_id);
	fputs(",\n  \"input_digest\": ", file);
	pqcdf_json_string(file, input_digest);
	fputs("\n}\n", file);
	if (fclose(file) != 0) {
		(void)unlink(path);
	}
}

static void pqcdf_write_metadata(const char *primitive, size_t algorithm_count,
	pqcdf_algorithm_name_fn algorithm_name, const char *const *property_names,
	size_t property_count) {
	const char *path = getenv("PQCDF_LIBFUZZER_METADATA_FILE");
	if (path == NULL || *path == '\0') {
		return;
	}
	char parent[PATH_MAX];
	const size_t path_length = strlen(path);
	if (path_length >= sizeof(parent)) {
		return;
	}
	memcpy(parent, path, path_length + 1);
	char *slash = strrchr(parent, '/');
	if (slash != NULL) {
		*slash = '\0';
		if (!pqcdf_make_directories(parent)) {
			return;
		}
	}
	char temporary[PATH_MAX];
	if (snprintf(temporary, sizeof(temporary), "%s.%ld.tmp", path, (long)getpid()) >=
		(int)sizeof(temporary)) {
		return;
	}
	FILE *file = fopen(temporary, "w");
	if (file == NULL) {
		return;
	}
	fputs("{\n  \"format_version\": 1,\n  \"primitive\": ", file);
	pqcdf_json_string(file, primitive);
	fputs(",\n  \"enabled_algorithms\": [", file);
	int first = 1;
	for (size_t i = 0; i < algorithm_count; ++i) {
		const char *name = algorithm_name(i);
		if (name == NULL) {
			continue;
		}
		if (!first) {
			fputs(", ", file);
		}
		pqcdf_json_string(file, name);
		first = 0;
	}
	fputs("],\n  \"property_ids\": [", file);
	for (size_t i = 0; i < property_count; ++i) {
		if (i != 0) {
			fputs(", ", file);
		}
		pqcdf_json_string(file, property_names[i]);
	}
	fputs("]\n}\n", file);
	if (fclose(file) == 0) {
		(void)rename(temporary, path);
	} else {
		(void)unlink(temporary);
	}
}

#endif
