#include "fuzz_common.h"

#include <oqs/kem.h>
#include <oqs/oqs.h>
#include <oqs/rand.h>

static const char *const pqcdf_kem_properties[] = {
	"kem_roundtrip",
	"kem_decaps_c",
	"kem_decaps_sk",
	"kem_encaps_pk",
	"kem_keygen_badrng",
	"kem_encaps_badrng",
};

static const char *pqcdf_kem_property_name(uint8_t property) {
	switch (property) {
	case PQCDF_KEM_PROPERTY_ROUNDTRIP:
		return "kem_roundtrip";
	case PQCDF_KEM_PROPERTY_DECAPS_C:
		return "kem_decaps_c";
	case PQCDF_KEM_PROPERTY_DECAPS_SK:
		return "kem_decaps_sk";
	case PQCDF_KEM_PROPERTY_ENCAPS_PK:
		return "kem_encaps_pk";
	case PQCDF_KEM_PROPERTY_KEYGEN_BADRNG:
		return "kem_keygen_badrng";
	case PQCDF_KEM_PROPERTY_ENCAPS_BADRNG:
		return "kem_encaps_badrng";
	default:
		return NULL;
	}
}

static const char *pqcdf_status_from_rc(OQS_STATUS rc) {
	return rc == OQS_SUCCESS ? pqcdf_outcome_name(PQCDF_OUTCOME_OK) :
		pqcdf_outcome_name(PQCDF_OUTCOME_OPERATION_ERROR);
}

static OQS_STATUS pqcdf_kem_default_keypair(OQS_KEM *kem, uint8_t *public_key,
	uint8_t *secret_key) {
	(void)OQS_randombytes_switch_algorithm("system");
	const OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	return rc;
}

static OQS_STATUS pqcdf_kem_default_encaps(OQS_KEM *kem, uint8_t *ciphertext,
	uint8_t *shared_secret, const uint8_t *public_key) {
	(void)OQS_randombytes_switch_algorithm("system");
	const OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	return rc;
}

static OQS_STATUS pqcdf_kem_default_decaps(OQS_KEM *kem, uint8_t *shared_secret,
	const uint8_t *ciphertext, const uint8_t *secret_key) {
	(void)OQS_randombytes_switch_algorithm("system");
	const OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	return rc;
}

static void pqcdf_kem_diagnostic(const char *algorithm, const char *operation,
	OQS_STATUS deterministic_rc, OQS_STATUS default_rc, const pqcdf_envelope *envelope) {
	pqcdf_record_operation_diagnostic("kem", algorithm, operation,
		pqcdf_status_from_rc(deterministic_rc), pqcdf_status_from_rc(default_rc),
		envelope->raw, envelope->raw_size);
}

static void pqcdf_record_kem_roundtrip_failure(const char *algorithm,
	const pqcdf_envelope *envelope) {
	pqcdf_record_finding("kem", algorithm, "kem_roundtrip", "EXPECT_EQUAL",
		"non_malleability", "functional_roundtrip_failure",
		pqcdf_outcome_name(PQCDF_OUTCOME_OK),
		pqcdf_outcome_name(PQCDF_OUTCOME_INVARIANT_VIOLATION), 1, 0,
		"OBSERVED_DIFFERENT", envelope->raw, envelope->raw_size);
}

static void pqcdf_run_kem(const pqcdf_envelope *envelope, const char *algorithm, OQS_KEM *kem) {
	const size_t public_key_len = kem->length_public_key;
	const size_t secret_key_len = kem->length_secret_key;
	const size_t ciphertext_len = kem->length_ciphertext;
	const size_t shared_secret_len = kem->length_shared_secret;

	uint8_t *public_key = pqcdf_alloc(public_key_len);
	uint8_t *secret_key = pqcdf_alloc(secret_key_len);
	uint8_t *ciphertext = pqcdf_alloc(ciphertext_len);
	uint8_t *shared_secret_encaps = pqcdf_alloc(shared_secret_len);
	uint8_t *shared_secret_decaps = pqcdf_alloc(shared_secret_len);
	uint8_t *mutated_ciphertext = pqcdf_alloc(ciphertext_len);
	uint8_t *mutated_secret_key = pqcdf_alloc(secret_key_len);
	uint8_t *mutated_public_key = pqcdf_alloc(public_key_len);
	uint8_t *mutated_shared_secret = pqcdf_alloc(shared_secret_len);
	uint8_t *alternate_public_key = pqcdf_alloc(public_key_len);
	uint8_t *alternate_secret_key = pqcdf_alloc(secret_key_len);
	uint8_t *alternate_ciphertext = pqcdf_alloc(ciphertext_len);
	uint8_t *alternate_shared_secret = pqcdf_alloc(shared_secret_len);

	if (public_key == NULL || secret_key == NULL || ciphertext == NULL ||
		shared_secret_encaps == NULL || shared_secret_decaps == NULL ||
		mutated_ciphertext == NULL || mutated_secret_key == NULL ||
		mutated_public_key == NULL || mutated_shared_secret == NULL ||
		alternate_public_key == NULL || alternate_secret_key == NULL ||
		alternate_ciphertext == NULL || alternate_shared_secret == NULL) {
		goto cleanup;
	}

	pqcdf_seed_envelope_rng(envelope, 0);
	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_seed_envelope_rng(envelope, 0);
		const OQS_STATUS deterministic_rc = OQS_KEM_keypair(kem, public_key, secret_key);
		const OQS_STATUS default_rc = pqcdf_kem_default_keypair(kem, public_key, secret_key);
		pqcdf_kem_diagnostic(algorithm, "keypair", deterministic_rc, default_rc, envelope);
		goto cleanup;
	}

	pqcdf_seed_envelope_rng(envelope, 0);
	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_encaps, public_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_seed_envelope_rng(envelope, 0);
		const OQS_STATUS deterministic_rc = OQS_KEM_encaps(
			kem, ciphertext, shared_secret_encaps, public_key);
		const OQS_STATUS default_rc = pqcdf_kem_default_encaps(
			kem, ciphertext, shared_secret_encaps, public_key);
		pqcdf_kem_diagnostic(algorithm, "encaps", deterministic_rc, default_rc, envelope);
		goto cleanup;
	}

	rc = OQS_KEM_decaps(kem, shared_secret_decaps, ciphertext, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_seed_envelope_rng(envelope, 0);
		const OQS_STATUS deterministic_rc = OQS_KEM_decaps(
			kem, shared_secret_decaps, ciphertext, secret_key);
		const OQS_STATUS default_rc = pqcdf_kem_default_decaps(
			kem, shared_secret_decaps, ciphertext, secret_key);
		pqcdf_kem_diagnostic(algorithm, "decaps", deterministic_rc, default_rc, envelope);
		goto cleanup;
	}
	if (memcmp(shared_secret_encaps, shared_secret_decaps, shared_secret_len) != 0) {
		pqcdf_record_kem_roundtrip_failure(algorithm, envelope);
		goto cleanup;
	}

	/* The memory-safety profile intentionally stops at valid API lifecycles. */
	if (!pqcdf_is_semantic_profile()) {
		goto cleanup;
	}

	int property_exercised = 0;
	switch (envelope->property_id) {
	case PQCDF_KEM_PROPERTY_ROUNDTRIP:
		property_exercised = 1;
		break;

	case PQCDF_KEM_PROPERTY_DECAPS_C:
		if (!kem->ind_cca) {
			pqcdf_record_property_outcome("kem", algorithm, "kem_decaps_c", "skipped",
				envelope->raw, envelope->raw_size);
			break;
		}
		if (!pqcdf_mutate_copy(mutated_ciphertext, ciphertext, ciphertext_len, envelope)) {
			break;
		}
		property_exercised = 1;
		rc = OQS_KEM_decaps(kem, mutated_shared_secret, mutated_ciphertext, secret_key);
		if (rc == OQS_SUCCESS &&
			memcmp(shared_secret_encaps, mutated_shared_secret, shared_secret_len) == 0) {
			pqcdf_record_finding("kem", algorithm, "kem_decaps_c", "EXPECT_DIFFERENT",
				"malleability",
				pqcdf_is_noncanonical_mutation(envelope) ? "accepted_noncanonical_mutation" :
					"ciphertext_malleability",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_KEM_PROPERTY_DECAPS_SK:
		if (!pqcdf_mutate_copy(mutated_secret_key, secret_key, secret_key_len, envelope)) {
			break;
		}
		property_exercised = 1;
		rc = OQS_KEM_decaps(kem, mutated_shared_secret, ciphertext, mutated_secret_key);
		if (rc == OQS_SUCCESS &&
			memcmp(shared_secret_encaps, mutated_shared_secret, shared_secret_len) == 0) {
			pqcdf_record_finding("kem", algorithm, "kem_decaps_sk", "EXPECT_DIFFERENT",
				"malleability",
				pqcdf_is_noncanonical_mutation(envelope) ? "accepted_noncanonical_mutation" :
					"secret_key_malleability",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_KEM_PROPERTY_ENCAPS_PK:
		if (!pqcdf_mutate_copy(mutated_public_key, public_key, public_key_len, envelope)) {
			break;
		}
		if (pqcdf_is_sparse_pk_single_challenge_kem(algorithm)) {
			property_exercised = 1;
			pqcdf_record_oracle_assumption_outcome(
				"kem", algorithm, "kem_encaps_pk",
				"oracle_assumption_unsupported_sparse_pk_single_challenge",
				"single public-key byte mutation under one encapsulation challenge is not a valid generic public-key binding oracle for this sparse/matrix KEM family",
				envelope);
			break;
		}
		property_exercised = 1;
		pqcdf_seed_envelope_rng(envelope, 0);
		rc = OQS_KEM_encaps(kem, alternate_ciphertext, alternate_shared_secret,
			mutated_public_key);
		if (rc == OQS_SUCCESS &&
			memcmp(ciphertext, alternate_ciphertext, ciphertext_len) == 0 &&
			memcmp(shared_secret_encaps, alternate_shared_secret, shared_secret_len) == 0) {
			pqcdf_record_finding("kem", algorithm, "kem_encaps_pk", "EXPECT_DIFFERENT",
				"malleability", "public_key_ignored_or_malleable",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_KEM_PROPERTY_KEYGEN_BADRNG:
		property_exercised = 1;
		pqcdf_seed_envelope_rng(envelope, 1);
		rc = OQS_KEM_keypair(kem, alternate_public_key, alternate_secret_key);
		if (rc != OQS_SUCCESS) {
			pqcdf_seed_envelope_rng(envelope, 1);
			const OQS_STATUS deterministic_rc = OQS_KEM_keypair(
				kem, alternate_public_key, alternate_secret_key);
			const OQS_STATUS default_rc = pqcdf_kem_default_keypair(
				kem, alternate_public_key, alternate_secret_key);
			pqcdf_kem_diagnostic(algorithm, "keypair_rng_variant", deterministic_rc,
				default_rc, envelope);
		} else if (memcmp(public_key, alternate_public_key, public_key_len) == 0 &&
			memcmp(secret_key, alternate_secret_key, secret_key_len) == 0) {
			pqcdf_record_finding("kem", algorithm, "kem_keygen_badrng", "EXPECT_DIFFERENT",
				"malleability", "keygen_rng_ignored",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_KEM_PROPERTY_ENCAPS_BADRNG:
		property_exercised = 1;
		pqcdf_seed_envelope_rng(envelope, 1);
		rc = OQS_KEM_encaps(kem, alternate_ciphertext, alternate_shared_secret, public_key);
		if (rc != OQS_SUCCESS) {
			pqcdf_seed_envelope_rng(envelope, 1);
			const OQS_STATUS deterministic_rc = OQS_KEM_encaps(
				kem, alternate_ciphertext, alternate_shared_secret, public_key);
			const OQS_STATUS default_rc = pqcdf_kem_default_encaps(
				kem, alternate_ciphertext, alternate_shared_secret, public_key);
			pqcdf_kem_diagnostic(algorithm, "encaps_rng_variant", deterministic_rc,
				default_rc, envelope);
		} else if (memcmp(ciphertext, alternate_ciphertext, ciphertext_len) == 0 &&
			memcmp(shared_secret_encaps, alternate_shared_secret, shared_secret_len) == 0) {
			pqcdf_record_finding("kem", algorithm, "kem_encaps_badrng", "EXPECT_DIFFERENT",
				"malleability", "encaps_rng_ignored",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;
	default:
		break;
	}
	if (property_exercised) {
		pqcdf_record_property_outcome("kem", algorithm,
			pqcdf_kem_property_name(envelope->property_id), "property_exercised",
			envelope->raw, envelope->raw_size);
	}

cleanup:
	pqcdf_secure_free(secret_key, secret_key_len);
	pqcdf_secure_free(mutated_secret_key, secret_key_len);
	pqcdf_secure_free(alternate_secret_key, secret_key_len);
	pqcdf_secure_free(public_key, public_key_len);
	pqcdf_secure_free(mutated_public_key, public_key_len);
	pqcdf_secure_free(alternate_public_key, public_key_len);
	pqcdf_secure_free(ciphertext, ciphertext_len);
	pqcdf_secure_free(mutated_ciphertext, ciphertext_len);
	pqcdf_secure_free(alternate_ciphertext, ciphertext_len);
	pqcdf_secure_free(shared_secret_encaps, shared_secret_len);
	pqcdf_secure_free(shared_secret_decaps, shared_secret_len);
	pqcdf_secure_free(mutated_shared_secret, shared_secret_len);
	pqcdf_secure_free(alternate_shared_secret, shared_secret_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	static int initialized = 0;
	if (!initialized) {
		(void)OQS_init();
		initialized = 1;
	}

	const int algorithm_count = OQS_KEM_alg_count();
	pqcdf_write_metadata("kem", algorithm_count > 0 ? (size_t)algorithm_count : 0,
		OQS_KEM_alg_identifier, pqcdf_kem_properties,
		sizeof(pqcdf_kem_properties) / sizeof(pqcdf_kem_properties[0]));

	pqcdf_envelope envelope;
	if (!pqcdf_parse_envelope(data, size, &envelope) || envelope.primitive != PQCDF_PRIMITIVE_KEM ||
		pqcdf_kem_property_name(envelope.property_id) == NULL || algorithm_count <= 0 ||
		envelope.algorithm_index >= (uint32_t)algorithm_count) {
		return 0;
	}

	const char *algorithm = OQS_KEM_alg_identifier(envelope.algorithm_index);
	if (algorithm == NULL || !OQS_KEM_alg_is_enabled(algorithm)) {
		if (algorithm != NULL) {
			pqcdf_record_operation_diagnostic("kem", algorithm, "new",
				pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED),
				pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED), data, size);
		}
		return 0;
	}

	pqcdf_seed_envelope_rng(&envelope, 0);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	OQS_KEM *kem = OQS_KEM_new(algorithm);
	if (kem == NULL) {
		pqcdf_record_operation_diagnostic("kem", algorithm, "new",
			pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED),
			pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED), data, size);
		return 0;
	}

	pqcdf_run_kem(&envelope, algorithm, kem);
	OQS_KEM_free(kem);
	return 0;
}
