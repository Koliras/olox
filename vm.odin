package lox

import "base:runtime"
import "core:fmt"
import "core:mem"

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
vm_interpret :: proc(vm: ^VM, chunk: ^Chunk) -> Interpret_Error {
	vm.chunk = chunk
	vm.ip = chunk.code
	return vm_run(vm)
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
