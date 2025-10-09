package lox

import os "core:os/os2"

main :: proc() {
	vm: VM
	vm_init(&vm)
	chunk: Chunk

	const := chunk_add_const(&chunk, 1.2)
	chunk_write(&chunk, byte(Op_Code.Constant), 123)
	chunk_write(&chunk, byte(const), 123)

	const = chunk_add_const(&chunk, 3.4)
	chunk_write(&chunk, byte(Op_Code.Constant), 123)
	chunk_write(&chunk, byte(const), 123)

	chunk_write(&chunk, byte(Op_Code.Add), 123)

	const = chunk_add_const(&chunk, 5.6)
	chunk_write(&chunk, byte(Op_Code.Constant), 123)
	chunk_write(&chunk, byte(const), 123)

	chunk_write(&chunk, byte(Op_Code.Substract), 123)
	chunk_write(&chunk, byte(Op_Code.Negate), 123)

	chunk_write(&chunk, byte(Op_Code.Return), 123)
	// disassemble_chunk(&chunk, "test chunk")

	vm_interpret(&vm, &chunk)

	vm_free(&vm)
	chunk_free(&chunk)
	os.exit(0)
}
