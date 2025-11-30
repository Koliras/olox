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
	globals:   Table,
	strings:   Table,
	objects:   ^Object,
}
vm: VM

vm_init :: proc() {
	vm_reset_stack()
	vm.objects = nil
}


vm_reset_stack :: proc() {
	vm.stack_top = &vm.stack[0]
}

vm_free :: proc() {
	table_free(&vm.globals)
	table_free(&vm.strings)
	vm_free_objects()
}

vm_free_objects :: proc() {
	object := vm.objects
	for object != nil {
		next := object.next
		object_free(object)
		object = next
	}
}

vm_repl :: proc() {
	line: [1024]byte

	for {
		fmt.print("> ")

		if read_amount, read_err := os.read(os.stdin, line[:]); read_err != nil {
			fmt.print("\n")
			break
		}

		vm_interpret(line[:])
	}
}

vm_run_file :: proc(fp: string) {
	source, _ := _read_file(fp)
	defer delete(source)
	result := vm_interpret(source)

	if result == .Compile_Error {
		os.exit(65)
	} else if result == .Runtime_Error {
		os.exit(70)
	}
}

_read_file :: proc(path: string) -> (data: []byte, err: os.Error) {
	file, file_err := os.open(path)
	if file_err != nil {
		fmt.fprintfln(os_old.stderr, "Could not open file \"%s\".", path)
		os.exit(74)
	}

	defer os.close(file)

	file_size := os.file_size(file) or_return
	allocation_err: runtime.Allocator_Error
	data, allocation_err = make([]byte, file_size + 1)
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

vm_push :: proc(val: Value) {
	vm.stack_top^ = val
	vm.stack_top = mem.ptr_offset(vm.stack_top, 1)
}

vm_pop :: proc() -> Value {
	vm.stack_top = mem.ptr_offset(vm.stack_top, -1)
	return vm.stack_top^
}

vm_peek :: proc(distance: int) -> Value {
	return mem.ptr_offset(vm.stack_top, -1 - distance)^
}

Interpret_Error :: enum {
	None,
	Compile_Error,
	Runtime_Error,
}

vm_interpret :: proc(source: []byte) -> Interpret_Error {
	chunk: Chunk
	defer chunk_free(&chunk)
	if !compile(source, &chunk) {
		return .Compile_Error
	}

	vm.chunk = &chunk
	vm.ip = chunk.code

	result := vm_run()
	return result
}

vm_runtime_error :: proc(format: string, args: ..any) {
	fmt.fprintfln(os_old.stderr, format, ..args)
	instruction := uint(uintptr(vm.ip) - uintptr(vm.chunk.code) - 1)
	line := vm.chunk.lines[instruction]
	fmt.fprintf(os_old.stderr, "[line %d] in script\n", line)
	vm_reset_stack()
}

vm_run :: proc() -> Interpret_Error {

	read_byte :: #force_inline proc() -> byte {
		instruction := (cast(^byte)vm.ip)^
		vm.ip = cast([^]byte)(uintptr(vm.ip) + 1)
		return instruction
	}
	read_constant :: #force_inline proc() -> Value {
		return vm.chunk.constants.values[read_byte()]
	}
	read_string :: #force_inline proc() -> ^Object_String {
		return object_as_string(read_constant())
	}

	get_numbers :: #force_inline proc() -> (f64, f64, bool) {
		if !value_is_number(vm_peek(0)) || !value_is_number(vm_peek(1)) {
			vm_runtime_error("Operands must be numbers.")
			return 0, 0, false
		}
		return vm_pop().as.number, vm_pop().as.number, true
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

		instruction := Op_Code(read_byte())
		switch instruction {
		case .Constant:
			const := read_constant()
			vm_push(const)
		case .Nil:
			vm_push(value_nil())
		case .True:
			vm_push(value_bool(true))
		case .False:
			vm_push(value_bool(false))
		case .Pop:
			vm_pop()
		case .Get_Global:
			name := read_string()
			value, defined_var := table_get(&vm.globals, name)
			if !defined_var {
				vm_runtime_error("Undefined variable '%s'.", name.chars)
				return .Runtime_Error
			}
			vm_push(value)
		case .Define_Global:
			name := read_string()
			table_set(&vm.globals, name, vm_peek(0))
			vm_pop()
		case .Set_Global:
			name := read_string()
			if table_set(&vm.globals, name, vm_peek(0)) {
				table_delete(&vm.globals, name)
				vm_runtime_error("Undefined variable '%s'.", name.chars)
				return .Runtime_Error
			}
		case .Equal:
			b := vm_pop()
			a := vm_pop()
			vm_push(value_bool(values_equal(a, b)))
		case .Greater:
			b, a, ok := get_numbers()
			fmt.println("foo")
			if !ok do return .Runtime_Error
			vm_push(value_bool(a > b))
		case .Less:
			b, a, ok := get_numbers()
			if !ok do return .Runtime_Error
			vm_push(value_bool(a < b))
		case .Add:
			if object_is_type(vm_peek(0), .String) && object_is_type(vm_peek(1), .String) {
				vm_concatenate()
			} else if value_is_number(vm_peek(0)) && value_is_number(vm_peek(1)) {
				a, b := vm_pop().as.number, vm_pop().as.number
				vm_push(value_number(a + b))
			} else {
				vm_runtime_error("Operands must be two numbers or two strings.")
				return .Runtime_Error
			}
		case .Substract:
			b, a, ok := get_numbers()
			if !ok do return .Runtime_Error
			vm_push(value_number(a - b))
		case .Multiply:
			b, a, ok := get_numbers()
			if !ok do return .Runtime_Error
			vm_push(value_number(a * b))
		case .Devide:
			b, a, ok := get_numbers()
			if !ok do return .Runtime_Error
			vm_push(value_number(a / b))
		case .Not:
			vm_push(value_bool(value_is_falsey(vm_pop())))
		case .Negate:
			if !value_is_number(vm_peek(0)) {
				vm_runtime_error("Operand must be a number.")
				return .Runtime_Error
			}
			vm_push(value_number(-vm_pop().as.number))
		case .Print:
			value_print(vm_pop())
			fmt.printf("\n")
		case .Return:
			return .None
		}
	}
	return .None
}

vm_concatenate :: proc() {
	b, a := object_as_string(vm_pop()), object_as_string(vm_pop())
	length := a.length + b.length
	chars := allocate(byte, length + 1)
	mem.copy_non_overlapping(chars, a.chars, a.length)
	mem.copy_non_overlapping(&chars[a.length], b.chars, b.length)
	chars[length] = 0

	str := string_take(chars, length)
	vm_push(string_as_value(str))
}
