#
# METADATA
# description: >-
#   This package is reponsible for verifying the source container image associated with the image
#   being validated.
#
package policy.release.source_image

import rego.v1

import data.lib
import data.lib.tkn

# METADATA
# title: Exists
# description: Verify the source container image exists.
# custom:
#   short_name: exists
#   failure_msg: "%s"
#
deny contains result if {
	some error in _source_image_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

_source_image_errors contains error if {
	count(_source_images) == 0
	error := "No source image references found"
}

_source_image_errors contains error if {
	some img in _source_images
	not ec.oci.image_manifest(img)
	error := sprintf("Unable to access source image %q", [img])
}

_source_image_errors contains error if {
	some img in _source_images
	manifest := ec.oci.image_manifest(img)
	layers := object.get(manifest, "layers", [])
	count(layers) == 0
	error := sprintf("Source image has no layers %q", [img])
}

# _source_images is a set of image references. Each corresponding to the
# SOURCE_IMAGE_URL@SOURCE_IMAGE_DIGEST parameter of a source-build Task.
_source_images contains img if {
	some att in lib.pipelinerun_attestations
	some task in tkn.source_build_tasks(att)

	url := trim_space(tkn.task_result(task, "SOURCE_IMAGE_URL"))
	digest := trim_space(tkn.task_result(task, "SOURCE_IMAGE_DIGEST"))
	img := sprintf("%s@%s", [url, digest])
}
