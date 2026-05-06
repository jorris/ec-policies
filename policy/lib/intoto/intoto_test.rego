# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

package lib.intoto_test

import rego.v1

import data.lib.assertions
import data.lib.intoto

test_statements_from_raw_intoto_referrer if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
		"artifactType": "application/vnd.in-toto+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/image@sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
	}]

	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.blob as _mock_blob_raw_test_result

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
	statement.predicate.result == "PASSED"
}

test_statements_from_sigstore_bundle_referrer if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 200,
		# regal ignore:line-length
		"digest": "sha256:bbb0000000000000000000000000000000000000000000000000000000000bbb",
		"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/image@sha256:bbb0000000000000000000000000000000000000000000000000000000000bbb",
	}]

	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.blob as _mock_blob_sigstore_bundle

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
	statement.predicate.result == "PASSED"
}

test_statements_filters_unrelated_referrers if {
	mock_referrers := [
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 100,
			# regal ignore:line-length
			"digest": "sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"artifactType": "application/vnd.in-toto+json",
			# regal ignore:line-length
			"ref": "registry.io/repo/image@sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
		},
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 300,
			# regal ignore:line-length
			"digest": "sha256:ccc0000000000000000000000000000000000000000000000000000000000ccc",
			"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
			# regal ignore:line-length
			"ref": "registry.io/repo/image@sha256:ccc0000000000000000000000000000000000000000000000000000000000ccc",
		},
	]

	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.blob as _mock_blob_raw_test_result

	count(result) == 1
}

test_statements_empty_when_no_referrers if {
	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as []

	count(result) == 0
}

test_statements_by_predicate_filters_correctly if {
	mock_referrers := [
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 100,
			# regal ignore:line-length
			"digest": "sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"artifactType": "application/vnd.in-toto+json",
			# regal ignore:line-length
			"ref": "registry.io/repo/image@sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
		},
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 200,
			# regal ignore:line-length
			"digest": "sha256:ddd0000000000000000000000000000000000000000000000000000000000ddd",
			"artifactType": "application/vnd.in-toto+json",
			# regal ignore:line-length
			"ref": "registry.io/repo/image@sha256:ddd0000000000000000000000000000000000000000000000000000000000ddd",
		},
	]

	result := intoto.statements_by_predicate(intoto.predicate_test_result) with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.blob as _mock_blob_mixed_predicates

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
}

test_predicate_constants if {
	assertions.assert_equal(intoto.predicate_test_result, "https://in-toto.io/attestation/test-result/v0.1")
	assertions.assert_equal(intoto.predicate_vuln_scan, "https://in-toto.io/attestation/vulns/v0.2")
}

# Mock blob returning a raw in-toto test-result statement
_mock_blob_raw_test_result(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED", "resourceUri": "registry.io/repo/image@sha256:abc123"},
})

# Mock blob returning a Sigstore bundle with a DSSE envelope wrapping an in-toto statement
_mock_blob_sigstore_bundle(_) := json.marshal({
	"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
	"dsseEnvelope": {
		"payloadType": "application/vnd.in-toto+json",
		"payload": base64.encode(json.marshal({
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
			"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
			"predicate": {"result": "PASSED", "resourceUri": "registry.io/repo/image@sha256:abc123"},
		})),
		"signatures": [{"sig": "fakesig"}],
	},
})

# Mock blob that returns different predicates based on ref
_mock_blob_mixed_predicates(ref) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED"},
}) if {
	contains(ref, "aaa")
}

_mock_blob_mixed_predicates(ref) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"scanner": {"uri": "https://scanner.example.com"}},
}) if {
	contains(ref, "ddd")
}
