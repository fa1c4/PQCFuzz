#include "fuzz_common.h"

#include <oqs/oqs.h>
#include <oqs/rand.h>
#include <oqs/sig.h>

static const char *const pqcdf_sig_properties[] = {
	"sig_roundtrip",
	"sig_verify_sig",
	"sig_verify_m",
	"sig_verify_pk",
	"sig_sign_sk",
	"sig_keygen_badrng",
	"sig_sign_badrng",
};

static const char *pqcdf_sig_property_name(uint8_t property) {
	switch (property) {
	case PQCDF_SIG_PROPERTY_ROUNDTRIP:
		return "sig_roundtrip";
	case PQCDF_SIG_PROPERTY_VERIFY_SIG:
		return "sig_verify_sig";
	case PQCDF_SIG_PROPERTY_VERIFY_M:
		return "sig_verify_m";
	case PQCDF_SIG_PROPERTY_VERIFY_PK:
		return "sig_verify_pk";
	case PQCDF_SIG_PROPERTY_SIGN_SK:
		return "sig_sign_sk";
	case PQCDF_SIG_PROPERTY_KEYGEN_BADRNG:
		return "sig_keygen_badrng";
	case PQCDF_SIG_PROPERTY_SIGN_BADRNG:
		return "sig_sign_badrng";
	default:
		return NULL;
	}
}

static const char *pqcdf_sig_status_from_rc(OQS_STATUS rc) {
	return rc == OQS_SUCCESS ? pqcdf_outcome_name(PQCDF_OUTCOME_OK) :
		pqcdf_outcome_name(PQCDF_OUTCOME_OPERATION_ERROR);
}

static OQS_STATUS pqcdf_sig_default_keypair(OQS_SIG *sig, uint8_t *public_key,
	uint8_t *secret_key) {
	(void)OQS_randombytes_switch_algorithm("system");
	const OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	return rc;
}

static OQS_STATUS pqcdf_sig_default_sign(OQS_SIG *sig, uint8_t *signature,
	size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	(void)OQS_randombytes_switch_algorithm("system");
	const OQS_STATUS rc = OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	return rc;
}

static OQS_STATUS pqcdf_sig_default_verify(OQS_SIG *sig, const uint8_t *message,
	size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	(void)OQS_randombytes_switch_algorithm("system");
	const OQS_STATUS rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	return rc;
}

static void pqcdf_sig_diagnostic(const char *algorithm, const char *operation,
	OQS_STATUS deterministic_rc, OQS_STATUS default_rc, const pqcdf_envelope *envelope) {
	pqcdf_record_operation_diagnostic("sig", algorithm, operation,
		pqcdf_sig_status_from_rc(deterministic_rc), pqcdf_sig_status_from_rc(default_rc),
		envelope->raw, envelope->raw_size);
}

static void pqcdf_run_sig(const pqcdf_envelope *envelope, const char *algorithm, OQS_SIG *sig) {
	static const uint8_t empty_message = 0;
	const size_t public_key_len = sig->length_public_key;
	const size_t secret_key_len = sig->length_secret_key;
	const size_t max_signature_len = sig->length_signature;
	const size_t message_len = envelope->message_len;
	const uint8_t *message = message_len == 0 ? &empty_message : envelope->message;

	uint8_t *public_key = pqcdf_alloc(public_key_len);
	uint8_t *secret_key = pqcdf_alloc(secret_key_len);
	uint8_t *signature = pqcdf_alloc(max_signature_len);
	uint8_t *mutated_signature = pqcdf_alloc(max_signature_len);
	uint8_t *mutated_message = pqcdf_alloc(message_len);
	uint8_t *mutated_public_key = pqcdf_alloc(public_key_len);
	uint8_t *mutated_secret_key = pqcdf_alloc(secret_key_len);
	uint8_t *alternate_signature = pqcdf_alloc(max_signature_len);
	uint8_t *alternate_public_key = pqcdf_alloc(public_key_len);
	uint8_t *alternate_secret_key = pqcdf_alloc(secret_key_len);
	size_t signature_len = 0;
	size_t alternate_signature_len = 0;

	if (public_key == NULL || secret_key == NULL || signature == NULL ||
		mutated_signature == NULL || mutated_message == NULL || mutated_public_key == NULL ||
		mutated_secret_key == NULL || alternate_signature == NULL ||
		alternate_public_key == NULL || alternate_secret_key == NULL) {
		goto cleanup;
	}

	pqcdf_seed_envelope_rng(envelope, 0);
	OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		pqcdf_seed_envelope_rng(envelope, 0);
		const OQS_STATUS deterministic_rc = OQS_SIG_keypair(sig, public_key, secret_key);
		const OQS_STATUS default_rc = pqcdf_sig_default_keypair(sig, public_key, secret_key);
		pqcdf_sig_diagnostic(algorithm, "keypair", deterministic_rc, default_rc, envelope);
		goto cleanup;
	}

	pqcdf_seed_envelope_rng(envelope, 0);
	rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS || signature_len > max_signature_len) {
		pqcdf_seed_envelope_rng(envelope, 0);
		size_t deterministic_signature_len = 0;
		const OQS_STATUS deterministic_rc = OQS_SIG_sign(sig, signature,
			&deterministic_signature_len, message, message_len, secret_key);
		size_t default_signature_len = 0;
		const OQS_STATUS default_rc = pqcdf_sig_default_sign(sig, signature,
			&default_signature_len, message, message_len, secret_key);
		pqcdf_sig_diagnostic(algorithm, "sign", deterministic_rc, default_rc, envelope);
		goto cleanup;
	}

	rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		const OQS_STATUS deterministic_rc = OQS_SIG_verify(
			sig, message, message_len, signature, signature_len, public_key);
		const OQS_STATUS default_rc = pqcdf_sig_default_verify(
			sig, message, message_len, signature, signature_len, public_key);
		pqcdf_sig_diagnostic(algorithm, "verify", deterministic_rc, default_rc, envelope);
		goto cleanup;
	}

	if (!pqcdf_is_semantic_profile()) {
		goto cleanup;
	}

	int property_exercised = 0;
	switch (envelope->property_id) {
	case PQCDF_SIG_PROPERTY_ROUNDTRIP:
		property_exercised = 1;
		break;

	case PQCDF_SIG_PROPERTY_VERIFY_SIG:
		if (!pqcdf_mutate_copy(mutated_signature, signature, signature_len, envelope)) {
			break;
		}
		property_exercised = 1;
		rc = OQS_SIG_verify(sig, message, message_len, mutated_signature, signature_len, public_key);
		if (rc == OQS_SUCCESS) {
			pqcdf_record_finding("sig", algorithm, "sig_verify_sig", "EXPECT_DIFFERENT",
				"malleability",
				pqcdf_is_noncanonical_mutation(envelope) ? "accepted_noncanonical_mutation" :
					"signature_malleability",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_SIG_PROPERTY_VERIFY_M:
		if (!pqcdf_mutate_copy(mutated_message, message, message_len, envelope)) {
			break;
		}
		property_exercised = 1;
		rc = OQS_SIG_verify(sig, mutated_message, message_len, signature, signature_len, public_key);
		if (rc == OQS_SUCCESS) {
			pqcdf_record_finding("sig", algorithm, "sig_verify_m", "EXPECT_DIFFERENT",
				"malleability",
				pqcdf_is_noncanonical_mutation(envelope) ? "accepted_noncanonical_mutation" :
					"message_binding_failure",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_SIG_PROPERTY_VERIFY_PK:
		if (!pqcdf_mutate_copy(mutated_public_key, public_key, public_key_len, envelope)) {
			break;
		}
		if (pqcdf_is_falcon_norm_bound_verify_pk(algorithm)) {
			property_exercised = 1;
			pqcdf_record_oracle_assumption_outcome(
				"sig", algorithm, "sig_verify_pk",
				"oracle_assumption_unsupported_falcon_norm_bound_pk",
				"Falcon verification is a norm-bound relation; a single accepted public-key byte mutation is not by itself a generic verification-key binding failure",
				envelope);
			break;
		}
		property_exercised = 1;
		rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, mutated_public_key);
		if (rc == OQS_SUCCESS) {
			pqcdf_record_finding("sig", algorithm, "sig_verify_pk", "EXPECT_DIFFERENT",
				"malleability",
				pqcdf_is_noncanonical_mutation(envelope) ? "accepted_noncanonical_mutation" :
					"public_key_binding_failure",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_SIG_PROPERTY_SIGN_SK:
		if (!pqcdf_mutate_copy(mutated_secret_key, secret_key, secret_key_len, envelope)) {
			break;
		}
		property_exercised = 1;
		alternate_signature_len = 0;
		pqcdf_seed_envelope_rng(envelope, 0);
		rc = OQS_SIG_sign(sig, alternate_signature, &alternate_signature_len, message,
			message_len, mutated_secret_key);
		if (rc == OQS_SUCCESS && alternate_signature_len <= max_signature_len &&
			OQS_SIG_verify(sig, message, message_len, alternate_signature,
				alternate_signature_len, public_key) == OQS_SUCCESS &&
			alternate_signature_len == signature_len &&
			memcmp(alternate_signature, signature, signature_len) == 0) {
			pqcdf_record_finding("sig", algorithm, "sig_sign_sk", "EXPECT_DIFFERENT",
				"malleability", "secret_key_ignored_or_malleable",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_SIG_PROPERTY_KEYGEN_BADRNG:
		property_exercised = 1;
		pqcdf_seed_envelope_rng(envelope, 1);
		rc = OQS_SIG_keypair(sig, alternate_public_key, alternate_secret_key);
		if (rc != OQS_SUCCESS) {
			pqcdf_seed_envelope_rng(envelope, 1);
			const OQS_STATUS deterministic_rc = OQS_SIG_keypair(
				sig, alternate_public_key, alternate_secret_key);
			const OQS_STATUS default_rc = pqcdf_sig_default_keypair(
				sig, alternate_public_key, alternate_secret_key);
			pqcdf_sig_diagnostic(algorithm, "keypair_rng_variant", deterministic_rc,
				default_rc, envelope);
		} else if (memcmp(public_key, alternate_public_key, public_key_len) == 0 &&
			memcmp(secret_key, alternate_secret_key, secret_key_len) == 0) {
			pqcdf_record_finding("sig", algorithm, "sig_keygen_badrng", "EXPECT_DIFFERENT",
				"malleability", "keygen_rng_ignored",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;

	case PQCDF_SIG_PROPERTY_SIGN_BADRNG:
		if (pqcdf_is_deterministic_signature_no_external_sign_rng(algorithm)) {
			property_exercised = 1;
			pqcdf_record_oracle_assumption_outcome(
				"sig", algorithm, "sig_sign_badrng",
				"oracle_assumption_unsupported_deterministic_signature_rng",
				"this signature family is deterministic or derives signing randomness internally, so changing the external liboqs RNG stream is not a valid EXPECT_DIFFERENT oracle",
				envelope);
			break;
		}
		property_exercised = 1;
		alternate_signature_len = 0;
		pqcdf_seed_envelope_rng(envelope, 1);
		rc = OQS_SIG_sign(sig, alternate_signature, &alternate_signature_len, message,
			message_len, secret_key);
		if (rc != OQS_SUCCESS || alternate_signature_len > max_signature_len) {
			pqcdf_seed_envelope_rng(envelope, 1);
			size_t deterministic_signature_len = 0;
			const OQS_STATUS deterministic_rc = OQS_SIG_sign(sig, alternate_signature,
				&deterministic_signature_len, message, message_len, secret_key);
			size_t default_signature_len = 0;
			const OQS_STATUS default_rc = pqcdf_sig_default_sign(sig, alternate_signature,
				&default_signature_len, message, message_len, secret_key);
			pqcdf_sig_diagnostic(algorithm, "sign_rng_variant", deterministic_rc,
				default_rc, envelope);
		} else if (alternate_signature_len == signature_len &&
			memcmp(alternate_signature, signature, signature_len) == 0 &&
			OQS_SIG_verify(sig, message, message_len, alternate_signature,
				alternate_signature_len, public_key) == OQS_SUCCESS) {
			pqcdf_record_finding("sig", algorithm, "sig_sign_badrng", "EXPECT_DIFFERENT",
				"malleability", "sign_rng_ignored",
				pqcdf_outcome_name(PQCDF_OUTCOME_OK),
				pqcdf_outcome_name(PQCDF_OUTCOME_OK), 1, 1,
				"OBSERVED_EQUAL", envelope->raw, envelope->raw_size);
		}
		break;
	default:
		break;
	}
	if (property_exercised) {
		pqcdf_record_property_outcome("sig", algorithm,
			pqcdf_sig_property_name(envelope->property_id), "property_exercised",
			envelope->raw, envelope->raw_size);
	}

cleanup:
	pqcdf_secure_free(secret_key, secret_key_len);
	pqcdf_secure_free(mutated_secret_key, secret_key_len);
	pqcdf_secure_free(alternate_secret_key, secret_key_len);
	pqcdf_secure_free(public_key, public_key_len);
	pqcdf_secure_free(mutated_public_key, public_key_len);
	pqcdf_secure_free(alternate_public_key, public_key_len);
	pqcdf_secure_free(signature, max_signature_len);
	pqcdf_secure_free(mutated_signature, max_signature_len);
	pqcdf_secure_free(alternate_signature, max_signature_len);
	pqcdf_secure_free(mutated_message, message_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	static int initialized = 0;
	if (!initialized) {
		(void)OQS_init();
		initialized = 1;
	}

	const int algorithm_count = OQS_SIG_alg_count();
	pqcdf_write_metadata("sig", algorithm_count > 0 ? (size_t)algorithm_count : 0,
		OQS_SIG_alg_identifier, pqcdf_sig_properties,
		sizeof(pqcdf_sig_properties) / sizeof(pqcdf_sig_properties[0]));

	pqcdf_envelope envelope;
	if (!pqcdf_parse_envelope(data, size, &envelope) || envelope.primitive != PQCDF_PRIMITIVE_SIG ||
		pqcdf_sig_property_name(envelope.property_id) == NULL || algorithm_count <= 0 ||
		envelope.algorithm_index >= (uint32_t)algorithm_count) {
		return 0;
	}

	const char *algorithm = OQS_SIG_alg_identifier(envelope.algorithm_index);
	if (algorithm == NULL || !OQS_SIG_alg_is_enabled(algorithm)) {
		if (algorithm != NULL) {
			pqcdf_record_operation_diagnostic("sig", algorithm, "new",
				pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED),
				pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED), data, size);
		}
		return 0;
	}

	pqcdf_seed_envelope_rng(&envelope, 0);
	OQS_randombytes_custom_algorithm(&pqcdf_randombytes);
	OQS_SIG *sig = OQS_SIG_new(algorithm);
	if (sig == NULL) {
		pqcdf_record_operation_diagnostic("sig", algorithm, "new",
			pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED),
			pqcdf_outcome_name(PQCDF_OUTCOME_UNSUPPORTED), data, size);
		return 0;
	}

	pqcdf_run_sig(&envelope, algorithm, sig);
	OQS_SIG_free(sig);
	return 0;
}
