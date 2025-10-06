package lox

import "core:fmt"
import "core:mem"

capacity_grow :: #force_inline proc(cap: int) -> int {
	return cap < 8 ? 8 : cap * 2
}

array_grow :: #force_inline proc(
	$T: typeid,
	ptr: rawptr,
	old_size: int,
	new_size: int,
	allocator := context.allocator,
) -> [^]T {
	return cast([^]T)reallocate(ptr, size_of(T) * old_size, size_of(T) * new_size, allocator)
}

reallocate :: proc(
	ptr: rawptr,
	old_size: int,
	new_size: int,
	allocator := context.allocator,
) -> rawptr {
	if new_size == 0 {
		free(ptr, allocator)
		return nil
	}
	new_mem, alloc_err := mem.resize(ptr, old_size, new_size, allocator = allocator)
	ensure(alloc_err == nil, fmt.aprintf("Reallocation failed with error %s", alloc_err))
	return new_mem
}
