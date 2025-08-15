package main

import "core:bufio"
import "core:fmt"
import "core:io"
import "core:mem"
import os "core:os/os2"
import "core:strconv"
import "core:strings"

had_error := false

main :: proc() {
	when ODIN_DEBUG {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		context.allocator = mem.tracking_allocator(&track)

		defer {
			if len(track.allocation_map) > 0 {
				fmt.eprintf("=== %v allocations not freed: ===\n", len(track.allocation_map))
				for _, entry in track.allocation_map {
					fmt.eprintf("- %v bytes @ %v\n", entry.size, entry.location)
				}
			}
			mem.tracking_allocator_destroy(&track)
		}
	}
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
	p := parser_from_tokens(tokens)
	expr, err := parser_parse(&p)
	fmt.printfln("Error: %v\nExpression: %#v", err, expr)
}

Scanner :: struct {
	src:       string,
	tokens:    [dynamic]Token,
	current:   int,
	line:      int,
	lex_start: int,
}

scanner_is_eof :: proc(s: ^Scanner) -> bool {
	return len(s.src) <= s.current
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
	Unknown,
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

scanner_scan_tokens :: proc(s: ^Scanner) -> []Token {
	if s.tokens == nil {
		s.tokens = make([dynamic]Token)
	}
	for !scanner_is_eof(s) {
		s.lex_start = s.current
		scanner_scan_token(s)
	}
	append(&s.tokens, Token{line = s.line, kind = .EOF})
	return s.tokens[:]
}

scanner_advance :: proc(s: ^Scanner) -> byte {
	cur := s.src[s.current]
	s.current += 1
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
		scanner_add_token(s, .Minus, "-")
	case '+':
		scanner_add_token(s, .Plus, "+")
	case ';':
		scanner_add_token(s, .Semicolon)
	case '*':
		scanner_add_token(s, .Star, "*")
	case '/':
		if scanner_match(s, '/') {
			for scanner_peek(s) != '\n' && !scanner_is_eof(s) {
				scanner_advance(s)
			}
		} else if scanner_match(s, '*') {
			scanner_multiline_comment(s)
		} else {
			scanner_add_token(s, .Slash, "/")
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
			report(s.line, fmt.tprintf("Unexpected character. %s", s.current))
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

	val := s.src[s.lex_start + 1:s.current - 1]
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

	str := s.src[s.lex_start:s.current]
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
	text := s.src[s.lex_start:s.current]
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
scanner_add_token_with_lexeme :: proc(s: ^Scanner, kind: Token_Kind, lexeme: string) {
	append(&s.tokens, Token{kind = kind, line = s.line, lexeme = lexeme})
}
scanner_add_token :: proc {
	scanner_add_simple_token,
	scanner_add_token_with_lexeme,
	scanner_add_token_with_literal,
}

scanner_peek :: proc(s: ^Scanner) -> byte {
	if scanner_is_eof(s) do return 0
	return s.src[s.current]
}
scanner_peek_next :: proc(s: ^Scanner) -> byte {
	if s.current + 1 >= len(s.src) do return 0
	return s.src[s.current + 1]
}
scanner_match :: proc(s: ^Scanner, expected: byte) -> bool {
	if scanner_is_eof(s) do return false
	if s.src[s.current] != expected do return false

	s.current += 1
	return true
}

report :: proc(line: int, message: ..string) {
	fmt.printfln("[line %d] Error: %s", line, message)
	had_error = true
}

error :: proc(token: ^Token, msg: string) -> Parse_Error_Unexpected_Token {
	if token.kind == .EOF {
		report(token.line, " at end", msg)
	} else {
		report(token.line, " at '", token.lexeme, "'", msg)
	}
	return {token = token, message = msg}
}

Expr :: union {
	^Expr_Literal,
	^Expr_Unary,
	^Expr_Binary,
	^Expr_Grouping,
}

Expr_Binary :: struct {
	operator: ^Token,
	left:     Expr,
	right:    Expr,
}

Expr_Grouping :: struct {
	expression: Expr,
}

Expr_Literal :: struct {
	value: Token_Literal,
}

Expr_Unary :: struct {
	operator: ^Token,
	right:    Expr,
}

Parser :: struct {
	current: int,
	tokens:  []Token,
}

Parse_Error :: union {
	Parse_Error_Unexpected_Token,
}

Parse_Error_Unexpected_Token :: struct {
	token:   ^Token,
	message: string,
}

parser_parse :: proc(p: ^Parser) -> (Expr, Parse_Error) {
	return parser_expression(p)
}

parser_from_tokens :: proc(tokens: []Token) -> Parser {
	return Parser{tokens = tokens}
}

parser_expression :: proc(p: ^Parser, allocator := context.allocator) -> (Expr, Parse_Error) {
	return parser_equality(p, allocator)
}

parser_equality :: proc(
	p: ^Parser,
	allocator := context.allocator,
) -> (
	e: Expr,
	err: Parse_Error,
) {
	expr := parser_comparison(p, allocator) or_return

	for parser_match(p, {.Equal_Equal, .Equal_Equal}) {
		operator := parser_prev(p)
		right := parser_comparison(p, allocator) or_return
		bin := new(Expr_Binary, allocator)
		bin.right = right
		bin.left = expr
		bin.operator = operator
		expr = bin
	}
	return expr, nil
}

parser_comparison :: proc(
	p: ^Parser,
	allocator := context.allocator,
) -> (
	e: Expr,
	err: Parse_Error,
) {
	expr := parser_term(p, allocator) or_return

	for parser_match(p, {.Greater, .Greater_Equal, .Less, .Less_Equal}) {
		operator := parser_prev(p)
		right := parser_term(p, allocator) or_return
		bin := new(Expr_Binary, allocator)
		bin.right = right
		bin.operator = operator
		bin.left = expr
		expr = bin
	}
	return expr, nil
}

parser_match :: proc(p: ^Parser, tokens: []Token_Kind) -> bool {
	for kind in tokens {
		if parser_check(p, kind) {
			parser_advance(p)
			return true
		}
	}
	return false
}

parser_peek :: #force_inline proc(p: ^Parser) -> ^Token {
	return &p.tokens[p.current]
}

parser_prev :: #force_inline proc(p: ^Parser) -> ^Token {
	return &p.tokens[p.current - 1]
}

parser_is_eof :: #force_inline proc(p: ^Parser) -> bool {
	return parser_peek(p).kind == .EOF
}

parser_check :: proc(p: ^Parser, kind: Token_Kind) -> bool {
	if parser_is_eof(p) {
		return false
	}
	return parser_peek(p).kind == kind
}

parser_advance :: proc(p: ^Parser) -> ^Token {
	if !parser_is_eof(p) {
		p.current += 1
	}
	return parser_prev(p)
}

parser_term :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Parse_Error) {
	expr := parser_factor(p, allocator) or_return

	for parser_match(p, {.Minus, .Plus}) {
		operator := parser_prev(p)
		right := parser_factor(p, allocator) or_return
		bin := new(Expr_Binary, allocator)
		bin.right = right
		bin.operator = operator
		bin.left = expr
		expr = bin
	}
	return expr, nil
}

parser_factor :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Parse_Error) {
	expr := parser_unary(p, allocator) or_return

	for parser_match(p, {.Slash, .Star}) {
		operator := parser_prev(p)
		right := parser_unary(p) or_return
		bin := new(Expr_Binary, allocator)
		bin.right = right
		bin.operator = operator
		bin.left = expr
		expr = bin
	}
	return expr, nil
}

parser_unary :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Parse_Error) {
	if parser_match(p, {.Bang, .Minus}) {
		operator := parser_prev(p)
		right := parser_unary(p) or_return
		unary := new(Expr_Unary, allocator)
		unary.operator = operator
		unary.right = right
		return unary, nil
	}
	return parser_primary(p, allocator)
}

parser_primary :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Parse_Error) {
	if parser_match(p, {.False}) {
		expr := new(Expr_Literal, allocator)
		expr.value = false
		return expr, nil
	}
	if parser_match(p, {.True}) {
		expr := new(Expr_Literal, allocator)
		expr.value = true
		return expr, nil
	}
	if parser_match(p, {.Nil}) {
		expr := new(Expr_Literal, allocator)
		return expr, nil
	}

	if parser_match(p, {.Number, .String}) {
		expr := new(Expr_Literal, allocator)
		prev := parser_prev(p)
		expr.value = prev.literal
		return expr, nil
	}

	if parser_match(p, {.Left_Paren}) {
		expr := parser_expression(p, allocator) or_return
		tkn, parse_err := parser_consume(p, .Right_Paren, "Expect ')' after expression.")
		if parse_err != nil {
			return {}, parse_err
		}
		group := new(Expr_Grouping, allocator)
		group.expression = expr
		return group, nil
	}

	return {}, error(parser_peek(p), "Expect expression.")
}

parser_consume :: proc(p: ^Parser, kind: Token_Kind, msg: string) -> (^Token, Parse_Error) {
	if parser_check(p, kind) do return parser_advance(p), nil

	token := parser_peek(p)
	return nil, error(token, msg)
}

parser_sync :: proc(p: ^Parser) {
	parser_advance(p)

	for !parser_is_eof(p) {
		if parser_prev(p).kind == .Semicolon do return

		#partial switch parser_peek(p).kind {
		case .Return, .Class, .Var, .Fun, .If, .For, .While, .Print:
			return
		}

		parser_advance(p)
	}
}
