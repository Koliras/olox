package lox

import "core:mem"
TABLE_MAX_LOAD :: 0.75

Table :: struct {
	count:    int,
	capacity: int,
	entries:  [^]Entry,
}

Entry :: struct {
	key:   ^Object_String,
	value: Value,
}

table_free :: proc(table: ^Table) {
	free(table.entries)
	table^ = {}
}

table_set :: proc(table: ^Table, key: ^Object_String, value: Value) -> bool {
	if f32(table.count + 1) > f32(table.capacity) * TABLE_MAX_LOAD {
		capacity := capacity_grow(table.capacity)
		table_capacity_adjust(table, capacity)
	}

	entry := find_entry(table.entries, table.capacity, key)
	key_is_new := entry.key == nil
	if key_is_new && value_is_nil(entry.value) {
		table.count += 1
	}
	entry.key = key
	entry.value = value
	return key_is_new
}

find_entry :: proc(entries: [^]Entry, capacity: int, key: ^Object_String) -> ^Entry {
	index := key.hash % u32(capacity)
	tombstone: ^Entry = nil
	for {
		entry := &entries[index]
		if entry.key == nil {
			if value_is_nil(entry.value) {
				return tombstone != nil ? tombstone : entry
			}
			if tombstone == nil {
				tombstone = entry
			}
		} else if entry.key == key {
			return entry
		}
		index = (index + 1) % u32(capacity)
	}
}

table_capacity_adjust :: proc(table: ^Table, capacity: int) {
	entries := allocate(Entry, capacity)
	table.count = 0

	for idx := 0; idx < table.capacity; idx += 1 {
		entry := &table.entries[idx]
		if entry.key == nil do continue

		destination := find_entry(entries, capacity, entry.key)
		destination^ = entry^
		table.count += 1
	}

	free(table.entries)
	table.entries = entries
	table.capacity = capacity
}

table_add_all :: proc(from, to: ^Table) {
	for idx := 0; idx < from.capacity; idx += 1 {
		entry := &from.entries[idx]
		if entry.key == nil do continue

		table_set(to, entry.key, entry.value)
	}
}

table_get :: proc(table: ^Table, key: ^Object_String) -> (Value, bool) {
	if table.count == 0 do return {}, false

	entry := find_entry(table.entries, table.capacity, key)
	if entry.key == nil do return {}, false

	return entry.value, true
}

table_delete :: proc(table: ^Table, key: ^Object_String) -> bool {
	if table.count == 0 do return false
	entry := find_entry(table.entries, table.capacity, key)
	if entry.key == nil do return false

	entry.key = nil
	entry.value = value_bool(true)
	return true
}

table_find_string :: proc(
	table: ^Table,
	chars: [^]byte,
	length: int,
	hash: u32,
) -> ^Object_String {
	if table.count == 0 do return nil
	idx := hash % u32(table.capacity)
	for {
		entry := &table.entries[idx]
		if entry.key == nil {
			if value_is_nil(entry.value) {
				return nil
			}
		} else if entry.key.length == length &&
		   entry.key.hash == hash &&
		   mem.compare_byte_ptrs(entry.key.chars, chars, length) == 0 {
			return entry.key
		}

		idx = (idx + 1) % u32(table.capacity)
	}
}

