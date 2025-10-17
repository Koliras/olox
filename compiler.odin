package lox

import "base:runtime"
import "core:fmt"

compile :: proc(source: []byte) {
	scanner: Scanner
	scanner_init(&scanner, source)

	line := -1

	for {
		token := scanner_scan_token(&scanner)
		if token.line != line {
			fmt.printf("%4d ", token.line)
			line = token.line
		} else {
			fmt.print("  | ")
		}
		fmt.printf(
			"%s '%s'\n",
			token.type,
			transmute(string)runtime.Raw_String{len = token.length, data = token.start},
		)

		if token.type == .Eof do break
	}
}
