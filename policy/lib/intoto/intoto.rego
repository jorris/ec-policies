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

# TODO(EC-1773): Confirm the artifact type once the test task implementation is finalized.
_artifact_type := "application/vnd.in-toto+json"

# statements returns the set of unsigned in-toto statements attached to the
# image as OCI referrers. Trust is established via Chains provenance (EC-1774),
# not via signatures on the statements themselves.
statements contains statement if {
	some referrer in ec.oci.image_referrers(input.image.ref)
	referrer.artifactType == _artifact_type
	blob := ec.oci.blob(referrer.ref)
	statement := json.unmarshal(blob)
	statement._type == "https://in-toto.io/Statement/v1"
}

# Filter statements by predicate type.
statements_by_predicate(predicate_type) := {statement |
	some statement in statements
	statement.predicateType == predicate_type
}

predicate_test_result := "https://in-toto.io/attestation/test-result/v0.1"

predicate_vuln_scan := "https://in-toto.io/attestation/vulns/v0.2"
