package lox

import os "core:os/os2"

main :: proc() {
	chunk: Chunk

	const := chunk_add_const(&chunk, 1.2)
	chunk_write(&chunk, byte(Op_Code.Constant), 123)
	chunk_write(&chunk, byte(const), 123)

	chunk_write(&chunk, byte(Op_Code.Return), 123)
	disassemble_chunk(&chunk, "test chunk")
	chunk_free(&chunk)
	os.exit(0)
}
