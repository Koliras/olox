package lox

import "core:fmt"
Value :: f64

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
	fmt.printf("%#v", val)
}
