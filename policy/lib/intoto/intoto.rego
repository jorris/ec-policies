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

package lib.intoto

import rego.v1

# Artifact types used to discover in-toto attestations attached as OCI referrers.
# TODO(EC-1773): Confirm the artifact type once the test task implementation is finalized.
# Sigstore bundle format used by cosign attest.
_sigstore_bundle_type := "application/vnd.dev.sigstore.bundle.v0.3+json"

# Raw in-toto statement format.
_intoto_statement_type := "application/vnd.in-toto+json"

_artifact_types := {
	_sigstore_bundle_type,
	_intoto_statement_type,
}

# statements returns the set of in-toto statements attached to the image as OCI referrers.
# Supports both raw in-toto JSON and Sigstore bundle (DSSE envelope) formats.
statements contains statement if {
	some referrer in ec.oci.image_referrers(input.image.ref)
	referrer.artifactType in _artifact_types
	blob := ec.oci.blob(referrer.ref)
	statement := _parse_statement(blob)
}

# Filter statements by predicate type.
statements_by_predicate(predicate_type) := {statement |
	some statement in statements
	statement.predicateType == predicate_type
}

# Predicate type constants for convenience.
predicate_test_result := "https://in-toto.io/attestation/test-result/v0.1"

predicate_vuln_scan := "https://in-toto.io/attestation/vulns/v0.2"

# Parse a blob as a raw in-toto statement (direct JSON).
_parse_statement(blob) := statement if {
	parsed := json.unmarshal(blob)
	parsed._type == "https://in-toto.io/Statement/v1"
	statement := parsed
}

# Parse a blob as a Sigstore bundle containing a DSSE envelope with an in-toto payload.
_parse_statement(blob) := statement if {
	bundle := json.unmarshal(blob)
	envelope := bundle.dsseEnvelope
	envelope.payloadType == "application/vnd.in-toto+json"
	statement := json.unmarshal(base64.decode(envelope.payload))
}
