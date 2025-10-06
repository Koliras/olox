package lox

import "core:fmt"
disassemble_chunk :: proc(c: ^Chunk, name: string) {
	fmt.printfln("== %s ==", name)

	for offset := 0; offset < c.count; {
		offset = disassemble_instruction(c, offset)
	}
}

disassemble_instruction :: proc(c: ^Chunk, offset: int) -> int {
	fmt.printf("%04d ", offset)

	if offset > 0 && c.lines[offset] == c.lines[offset - 1] {
		fmt.print("   | ")
	} else {
		fmt.printf("%4d ", c.lines[offset])
	}

	instruction := cast(Op_Code)c.code[offset]
	switch instruction {
	case .Constant:
		return constant_instruction("OP_CONSTANT", c, offset)
	case .Return:
		return simple_instruction("OP_RETURN", offset)
	case:
		fmt.printfln("Unknownd opcode %d", instruction)
		return offset + 1
	}
}

simple_instruction :: proc(name: string, offset: int) -> int {
	fmt.println(name)
	return offset + 1
}

constant_instruction :: proc(name: string, chunk: ^Chunk, offset: int) -> int {
	const := chunk.code[offset + 1]
	fmt.printf("%-16s %4d '", name, const)
	value_print(chunk.constants.values[const])
	fmt.printf("'\n")
	return offset + 2
}
