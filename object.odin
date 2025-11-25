package lox

import "core:fmt"
import "core:mem"

Object_Type :: enum {
	String,
}

Object :: struct {
	type: Object_Type,
	next: ^Object,
}

Object_String :: struct {
	object: Object,
	length: int,
	chars:  [^]byte,
	hash:   u32,
}

object_type :: #force_inline proc(val: Value) -> Object_Type {
	return val.as.object.type
}

object_is_type :: #force_inline proc(val: Value, type: Object_Type) -> bool {
	return value_is_object(val) && val.as.object.type == type
}

object_as_string :: #force_inline proc(val: Value) -> ^Object_String {
	return cast(^Object_String)rawptr(val.as.object)
}
object_as_cstring :: #force_inline proc(val: Value) -> [^]byte {
	return (cast(^Object_String)rawptr(val.as.object)).chars
}

object_allocate :: #force_inline proc($T: typeid, obj_type: Object_Type) -> ^T {
	object := cast(^Object)reallocate(nil, 0, size_of(T))
	object.type = obj_type
	object.next = vm.objects
	vm.objects = object
	return cast(^T)rawptr(object)
}

object_free :: proc(object: ^Object) {
	switch object.type {
	case .String:
		str := cast(^Object_String)rawptr(object)
		free(str.chars)
		free(object)
	}
}

object_print :: proc(val: Value) {
	switch object_type(val) {
	case .String:
		fmt.printf("%s", object_as_cstring(val))
	}
}

string_as_object :: #force_inline proc(str: ^Object_String) -> ^Object {
	return cast(^Object)rawptr(str)
}
string_as_value :: #force_inline proc(str: ^Object_String) -> Value {
	return value_object(string_as_object(str))

}

string_take :: proc(chars: [^]byte, len: int) -> ^Object_String {
	hash := string_hash(chars, len)
	interned := table_find_string(&vm.strings, chars, len, hash)
	if interned != nil {
		free(chars)
		return interned
	}
	return string_allocate(chars, len, hash)
}

string_copy :: proc(chars: [^]byte, len: int) -> ^Object_String {
	hash := string_hash(chars, len)
	interned := table_find_string(&vm.strings, chars, len, hash)
	if interned != nil {
		return interned
	}
	heap_chars := allocate(byte, len + 1)
	mem.copy_non_overlapping(heap_chars, chars, len)
	heap_chars[len] = 0
	return string_allocate(heap_chars, len, hash)
}

string_allocate :: proc(chars: [^]byte, len: int, hash: u32) -> ^Object_String {
	str := object_allocate(Object_String, .String)
	str.length = len
	str.chars = chars
	str.hash = hash
	table_set(&vm.strings, str, value_nil())
	return str
}

string_hash :: proc(chars: [^]byte, len: int) -> u32 {
	hash: u32 = 2166136261
	for i := 0; i < len; i += 1 {
		hash ~= cast(u32)chars[i]
		hash *= 16777619
	}
	return hash
}

