package main

import "core:bufio"
import "core:fmt"
import "core:io"
import os "core:os/os2"
import "core:strconv"
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
	scanner := Scanner {
		src = code,
	}
	tokens := scanner_scan_tokens(&scanner)

	for token in tokens {
		fmt.println(token)
	}
}

Scanner :: struct {
	src:       string,
	tokens:    [dynamic]Token,
	pos:       int,
	line:      int,
	lex_start: int,
}

scanner_is_eof :: proc(s: ^Scanner) -> bool {
	return len(s.src) <= s.pos
}

Token :: struct {
	kind:    Token_Kind,
	lexeme:  string,
	line:    int,
	literal: Token_Literal,
}

Token_Literal :: union {
	string,
	bool,
	f64,
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

scanner_scan_tokens :: proc(s: ^Scanner) -> [dynamic]Token {
	if s.tokens == nil {
		s.tokens = make([dynamic]Token)
	}
	for !scanner_is_eof(s) {
		s.lex_start = s.pos
		scanner_scan_token(s)
	}
	append(&s.tokens, Token{line = s.line, kind = .EOF})
	return s.tokens
}

scanner_advance :: proc(s: ^Scanner) -> byte {
	cur := s.src[s.pos]
	s.pos += 1
	return cur
}

scanner_scan_token :: proc(s: ^Scanner) {
	c := scanner_advance(s)

	switch c {
	case '(':
		scanner_add_token(s, .Left_Paren)
	case ')':
		scanner_add_token(s, .Right_Paren)
	case '{':
		scanner_add_token(s, .Left_Brace)
	case '}':
		scanner_add_token(s, .Right_Brace)
	case ',':
		scanner_add_token(s, .Comma)
	case '.':
		next := scanner_peek(s)
		if next >= '0' && next <= '9' {
			report(s.line, "Leading dot before number")
			return
		}
		scanner_add_token(s, .Dot)
	case '-':
		scanner_add_token(s, .Minus)
	case '+':
		scanner_add_token(s, .Plus)
	case ';':
		scanner_add_token(s, .Semicolon)
	case '*':
		scanner_add_token(s, .Star)
	case '/':
		if scanner_match(s, '/') {
			for scanner_peek(s) != '\n' && !scanner_is_eof(s) {
				scanner_advance(s)
			}
		} else if scanner_match(s, '*') {
			scanner_multiline_comment(s)
		} else {
			scanner_add_token(s, .Slash)
		}
	case '\n':
		s.line += 1
	case ' ', '\t', '\r':
	case '"':
		scanner_string(s)
	case '0' ..= '9':
		scanner_number(s)
	case '=':
		scanner_add_token(s, scanner_match(s, '=') ? .Equal_Equal : .Equal)
	case '!':
		scanner_add_token(s, scanner_match(s, '=') ? .Bang_Equal : .Bang)
	case '<':
		scanner_add_token(s, scanner_match(s, '=') ? .Less_Equal : .Less)
	case '>':
		scanner_add_token(s, scanner_match(s, '=') ? .Greater_Equal : .Greater)
	case:
		if is_alpha(c) {
			scanner_identifier(s)
		} else {
			report(s.line, fmt.tprintf("Unexpected character. %s", s.pos))
		}
	}
}

scanner_string :: proc(s: ^Scanner) {
	start_line := s.line
	for scanner_peek(s) != '"' && !scanner_is_eof(s) {
		if scanner_peek(s) == '\n' {
			s.line += 1
		}
		scanner_advance(s)
	}

	if scanner_is_eof(s) {
		report(s.line, "Unterminated string.")
		return
	}
	scanner_advance(s)

	val := s.src[s.lex_start + 1:s.pos - 1]
	scanner_add_full_token(s, {kind = .String, literal = val, line = start_line})
}

scanner_multiline_comment :: proc(s: ^Scanner) {
	depth := 1
	for depth > 0 {
		if scanner_is_eof(s) {
			break
		} else if scanner_peek(s) == '/' && scanner_peek_next(s) == '*' {
			depth += 1
			scanner_advance(s)
		} else if scanner_peek(s) == '*' && scanner_peek_next(s) == '/' {
			depth -= 1
			scanner_advance(s)
		} else if scanner_peek(s) == '\n' {
			s.line += 1
		}
		scanner_advance(s)
	}
}

scanner_number :: proc(s: ^Scanner) {
	for is_digit(scanner_peek(s)) {
		scanner_advance(s)
	}

	if scanner_peek(s) == '.' && is_digit(scanner_peek_next(s)) {
		scanner_advance(s)
		for is_digit(scanner_peek(s)) {
			scanner_advance(s)
		}
	}

	str := s.src[s.lex_start:s.pos]
	val, ok := strconv.parse_f64(str)
	if !ok {
		report(s.line, "Could not parse float number")
	}
	scanner_add_token(s, .Number, val)
}

is_digit :: #force_inline proc(c: byte) -> bool {
	return c >= '0' && c <= '9'
}
is_alpha :: #force_inline proc(c: byte) -> bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
}
is_alpha_numeric :: proc(c: byte) -> bool {
	return is_alpha(c) || is_digit(c)
}

scanner_identifier :: proc(s: ^Scanner) {
	for is_alpha_numeric(scanner_peek(s)) {
		scanner_advance(s)
	}
	text := s.src[s.lex_start:s.pos]
	type := Token_Kind.Identifier
	switch text {
	case "or":
		type = .Or
	case "and":
		type = .And
	case "if":
		type = .If
	case "class":
		type = .Class
	case "else":
		type = .Else
	case "false":
		type = .False
	case "true":
		type = .True
	case "for":
		type = .For
	case "fun":
		type = .Fun
	case "nil":
		type = .Nil
	case "print":
		type = .Print
	case "return":
		type = .Return
	case "super":
		type = .Super
	case "this":
		type = .This
	case "var":
		type = .Var
	case "while":
		type = .While
	}
	scanner_add_token(s, type)
}

scanner_add_simple_token :: proc(s: ^Scanner, kind: Token_Kind) {
	append(&s.tokens, Token{kind = kind, line = s.line})
}
scanner_add_token_with_literal :: proc(s: ^Scanner, kind: Token_Kind, literal: Token_Literal) {
	append(&s.tokens, Token{kind = kind, line = s.line, literal = literal})
}
scanner_add_full_token :: proc(s: ^Scanner, token: Token) {
	append(&s.tokens, token)
}
scanner_add_token :: proc {
	scanner_add_simple_token,
	scanner_add_token_with_literal,
}

scanner_peek :: proc(s: ^Scanner) -> byte {
	if scanner_is_eof(s) do return 0
	return s.src[s.pos]
}
scanner_peek_next :: proc(s: ^Scanner) -> byte {
	if s.pos + 1 >= len(s.src) do return 0
	return s.src[s.pos + 1]
}
scanner_match :: proc(s: ^Scanner, expected: byte) -> bool {
	if scanner_is_eof(s) do return false
	if s.src[s.pos] != expected do return false

	s.pos += 1
	return true
}

report :: proc(line: int, message: string) {
	fmt.printfln("[line %d] Error: %s", line, message)
	had_error = true
}
