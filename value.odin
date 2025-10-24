package lox

import "core:fmt"

Value_Type :: enum {
	Nil,
	Bool,
	Number,
}
Value :: struct {
	type: Value_Type,
	as:   struct #raw_union {
		boolean: bool,
		number:  f64,
	},
}

value_bool :: #force_inline proc(b: bool) -> Value {
	return {.Bool, {boolean = b}}
}
value_number :: #force_inline proc(n: f64) -> Value {
	return {.Number, {number = n}}
}
value_nil :: #force_inline proc() -> Value {
	return {}
}

value_is_bool :: #force_inline proc(val: Value) -> bool {
	return val.type == .Bool
}
value_is_nil :: #force_inline proc(val: Value) -> bool {
	return val.type == .Nil
}
value_is_number :: #force_inline proc(val: Value) -> bool {
	return val.type == .Number
}

value_is_falsey :: proc(val: Value) -> bool {
	return value_is_nil(val) || (value_is_bool(val) && !val.as.boolean)
}

values_equal :: proc(a, b: Value) -> bool {
	if a.type != b.type do return false
	switch a.type {
	case .Nil:
		return true
	case .Number:
		return a.as.number == b.as.number
	case .Bool:
		return a.as.boolean == b.as.boolean
	case:
		return false
	}
}

Value_Array :: struct {
	cap:    int,
	count:  int,
	values: [^]Value,
}

value_array_write :: proc(va: ^Value_Array, val: Value) {
	if va.cap < va.count + 1 {
		old_cap := va.cap
		va.cap = capacity_grow(old_cap)
		va.values = array_grow(Value, va.values, old_cap, va.cap)
	}

	va.values[va.count] = val
	va.count += 1
}


value_array_free :: proc(va: ^Value_Array, allocator := context.allocator) {
	free(va.values, allocator)
	va^ = {}
}

value_print :: proc(val: Value) {
	switch val.type {
	case .Bool:
		fmt.printf(val.as.boolean ? "true" : "false")
	case .Nil:
		fmt.printf("nil")
	case .Number:
		fmt.printf("%g", val.as.number)
	}
}
