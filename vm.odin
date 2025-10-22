package lox

import "base:runtime"
import "core:fmt"
import "core:mem"
import os_old "core:os"
import os "core:os/os2"

STACK_MAX :: 256

VM :: struct {
	chunk:     ^Chunk,
	ip:        [^]byte,
	stack:     [STACK_MAX]Value,
	stack_top: ^Value,
}

vm_init :: proc(vm: ^VM) {
	vm_reset_stack(vm)
}

vm_reset_stack :: proc(vm: ^VM) {
	vm.stack_top = &vm.stack[0]
}

vm_free :: proc(vm: ^VM) {}

vm_repl :: proc(vm: ^VM) {
	line: [1024]byte

	for {
		fmt.print("> ")

		if read_amount, read_err := os.read(os.stdin, line[:]); read_err != nil {
			fmt.print("\n")
			break
		}

		vm_interpret(vm, line[:])
	}
}

vm_run_file :: proc(vm: ^VM, fp: string, allocator := context.allocator) {
	source, _ := _read_file(fp, allocator)
	defer delete(source, allocator)
	result := vm_interpret(vm, source)

	if result == .Compile_Error {
		os.exit(65)
	} else if result == .Runtime_Error {
		os.exit(70)
	}
}

_read_file :: proc(path: string, allocator := context.allocator) -> (data: []byte, err: os.Error) {
	file, file_err := os.open(path)
	if file_err != nil {
		fmt.fprintfln(os_old.stderr, "Could not open file \"%s\".", path)
		os.exit(74)
	}

	defer os.close(file)

	file_size := os.file_size(file) or_return
	allocation_err: runtime.Allocator_Error
	data, allocation_err = make([]byte, file_size + 1, allocator)
	if allocation_err != nil {
		fmt.fprintfln(os_old.stderr, "Not enough memory to read \"%s\".", path)
		os.exit(74)
	}

	bytes_read, _ := os.read(file, data[:])
	if i64(bytes_read) < file_size {
		fmt.fprintfln(os_old.stderr, "Could not read file \"%s\".", path)
		os.exit(74)
	}

	data[bytes_read] = 0

	return data, nil
}

vm_push :: proc(vm: ^VM, val: Value) {
	vm.stack_top^ = val
	vm.stack_top = mem.ptr_offset(vm.stack_top, 1)
}

vm_pop :: proc(vm: ^VM) -> Value {
	vm.stack_top = mem.ptr_offset(vm.stack_top, -1)
	return vm.stack_top^
}

Interpret_Error :: enum {
	None,
	Compile_Error,
	Runtime_Error,
}
vm_interpret :: proc(vm: ^VM, source: []byte) -> Interpret_Error {
	chunk: Chunk
	defer chunk_free(&chunk)
	if !compile(source, &chunk) {
		return .Compile_Error
	}

	vm.chunk = &chunk
	vm.ip = chunk.code

	result := vm_run(vm)
	return result
}

vm_run :: proc(vm: ^VM) -> Interpret_Error {

	read_byte :: #force_inline proc(vm: ^VM) -> byte {
		instruction := (cast(^byte)vm.ip)^
		vm.ip = cast([^]byte)(uintptr(vm.ip) + 1)
		return instruction
	}
	read_constant :: #force_inline proc(vm: ^VM) -> Value {
		return vm.chunk.constants.values[read_byte(vm)]
	}

	get_numbers :: #force_inline proc(vm: ^VM) -> (Value, Value) {
		return vm_pop(vm), vm_pop(vm)
	}

	for {
		when ODIN_DEBUG {
			fmt.print("          ")
			for slot := &vm.stack[0]; slot < vm.stack_top; slot = mem.ptr_offset(slot, 1) {
				fmt.print("[ ")
				value_print(slot^)
				fmt.print(" ]")
			}
			fmt.print("\n")
			disassemble_instruction(vm.chunk, int(uintptr(vm.ip) - uintptr(vm.chunk.code)))
		}

		instruction := Op_Code(read_byte(vm))
		switch instruction {
		case .Constant:
			const := read_constant(vm)
			vm_push(vm, const)
		case .Add:
			b, a := get_numbers(vm)
			vm_push(vm, a + b)
		case .Substract:
			b, a := get_numbers(vm)
			vm_push(vm, a - b)
		case .Multiply:
			b, a := get_numbers(vm)
			vm_push(vm, a * b)
		case .Devide:
			b, a := get_numbers(vm)
			vm_push(vm, a / b)
		case .Negate:
			last := mem.ptr_offset(vm.stack_top, -1)
			last^ = -last^
		case .Return:
			value_print(vm_pop(vm))
			fmt.print("\n")
			return .None
		}
	}
	return .None
}
