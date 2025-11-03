package lox

import "core:fmt"
import os_old "core:os"
import os "core:os/os2"

main :: proc() {
	vm: VM
	vm_init()

	args := os.args
	if len(args) == 1 {
		vm_repl()
	} else if len(args) == 2 {
		vm_run_file(args[1])
	} else {
		fmt.fprintln(os_old.stderr, "Usage: olox [path]")
		os.exit(69)
	}

	vm_free()
	os.exit(0)
}

