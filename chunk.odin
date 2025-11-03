package lox

Op_Code :: enum u8 {
	Constant,
	Nil,
	True,
	False,
	Equal,
	Greater,
	Less,
	Add,
	Substract,
	Multiply,
	Devide,
	Not,
	Negate,
	Return,
}

Chunk :: struct {
	cap:       int,
	count:     int,
	code:      [^]byte,
	lines:     [^]int,
	constants: Value_Array,
}

chunk_write :: proc(c: ^Chunk, b: byte, line: int) {
	if c.cap < c.count + 1 {
		old_cap := c.cap
		c.cap = capacity_grow(old_cap)
		c.code = array_grow(byte, c.code, old_cap, c.cap)
		c.lines = array_grow(int, c.lines, old_cap, c.cap)
	}

	c.code[c.count] = b
	c.lines[c.count] = line
	c.count += 1
}


chunk_free :: proc(c: ^Chunk) {
	free(c.code)
	free(c.lines)
	value_array_free(&c.constants)
	c^ = {}
}

chunk_add_const :: proc(c: ^Chunk, val: Value) -> int {
	value_array_write(&c.constants, val)
	return c.constants.count - 1
}

