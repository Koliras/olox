package main

import "core:bufio"
import "core:fmt"
import "core:io"
import os "core:os/os2"
import "core:strings"

had_error := false

main :: proc() {
	args := os.args
	if len(args) > 2 {
		fmt.println("Usage: olox [script]")
		os.exit(1)
	} else if len(args) == 2 {
		run_file(args[1])
	} else {
		run_prompt()
	}
}

run_file :: proc(fpath: string) {
	fmt.println(fpath)
	f, ferr := os.open(fpath)
	if ferr != nil {
		fmt.printfln("Could not open %s file. Error %s received", fpath, ferr)
		os.exit(1)
	}
	content, content_err := os.read_entire_file_from_file(f, context.allocator)
	if content_err != nil {
		fmt.printfln("Failed to read content of %s with error %s", fpath, content_err)
		os.exit(1)
	}
	run_code(string(content))
	if had_error {
		os.exit(65)
	}
}
run_prompt :: proc() {
	r := io.to_reader(os.stdin.stream)
	w := io.to_writer(os.stdout.stream)

	sb := strings.builder_make()
	buf: [4096]byte
	line := ""
	prompt_loop: for {
		io.write_string(w, "> ")
		for {
			n, _ := io.read_at_least(r, buf[:], len(buf))
			if n == 0 {
				break prompt_loop
			}
			fmt.println(n)

			strings.write_bytes(&sb, buf[:n])
			if buf[n - 1] == '\n' {
				line = strings.to_string(sb)
				strings.builder_reset(&sb)
				break
			}
		}
		run_code(line)
		had_error = false
	}
}

run_code :: proc(code: string) {
	fmt.println(code)
	scanner := Scanner{code}
	tokens := scanner_scan_tokens(&scanner)

	for token in tokens {
		fmt.println(token)
	}
}

Scanner :: struct {
	src: string,
}

Token :: struct {
	kind: Token_Kind,
}

Token_Kind :: enum u8 {
	// single character tokens
	Left_Paren,
	Right_Paren,
	Left_Brace,
	Right_Brace,
	Comma,
	Dot,
	Minus,
	Plus,
	Semicolon,
	Slash,
	Star,

	// 1-2 char tokens
	Bang,
	Bang_Equal,
	Equal,
	Equal_Equal,
	Less,
	Less_Equal,
	Greater,
	Greater_Equal,

	// literals
	Identifier,
	String,
	Number,

	// keywords
	And,
	Class,
	Else,
	False,
	Fun,
	For,
	If,
	Nil,
	Or,
	Print,
	Return,
	Super,
	This,
	True,
	Var,
	While,

	//
	EOF,
}

scanner_scan_tokens :: proc(scanner: ^Scanner) -> []Token {
	return {}
}

report :: proc(line: int, message: string) {
	fmt.printfln("[line %d] Error: %s", line, message)
	had_error = true
}
