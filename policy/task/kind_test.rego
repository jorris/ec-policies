package policy.task.kind_test

import data.lib
import data.policy.task.kind
import future.keywords.if

test_unexpected_kind if {
	lib.assert_equal_results(kind.deny, {{
		"code": "kind.expected_kind",
		"msg": "Unexpected kind 'Foo' for task definition",
	}}) with input.kind as "Foo"
}

test_expected_kind if {
	lib.assert_empty(kind.deny) with input as {"kind": "Task"}
}

test_kind_not_found if {
	lib.assert_equal_results(kind.deny, {{
		"code": "kind.kind_present",
		"msg": "Required field 'kind' not found",
	}}) with input as {"bad": "Foo"}
}
