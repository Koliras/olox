package lox

import "core:fmt"
import os_old "core:os"
import os "core:os/os2"

main :: proc() {
	vm: VM
	vm_init(&vm)

	args := os.args
	if len(args) == 1 {
		vm_repl(&vm)
	} else if len(args) == 2 {
		vm_run_file(&vm, args[1])
	} else {
		fmt.fprintln(os_old.stderr, "Usage: olox [path]")
		os.exit(69)
	}

	vm_free(&vm)
	os.exit(0)
}
