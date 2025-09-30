package main

import "base:runtime"
import "core:bufio"
import "core:fmt"
import "core:io"
import "core:mem"
import os "core:os/os2"
import "core:strconv"
import "core:strings"
import "core:time"

had_error := false
had_runtime_error := false

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
	if had_runtime_error {
		os.exit(70)
	}
}
run_prompt :: proc() {
	r := io.to_reader(os.stdin.stream)
	w := io.to_writer(os.stdout.stream)

	sb := strings.builder_make()
	buf: [1]byte
	line := ""
	prompt_loop: for {
		io.write_string(w, "> ")
		for {
			n, _ := io.read_at_least(r, buf[:], len(buf))
			if n == 0 {
				break prompt_loop
			}

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

	p := parser_from_tokens(tokens)
	stmts, err := parser_parse(&p)
	if err != nil {
		return
	}
	global_env := env_init()
	interpreter := Interpreter {
		globals = &global_env,
		env     = &global_env,
		locals  = make(map[Expr]int),
	}
	env_define(
		interpreter.globals,
		"clock",
		Function {
			decl = &Stmt_Function {
				name = &Token{lexeme = "clock", kind = .Identifier},
				call = proc(
					i: ^Interpreter,
					fn: ^Function,
					args: []Value,
					allocator: runtime.Allocator,
				) -> (
					Value,
					Error,
				) {
					return f64(time.tick_now()._nsec / 1_000_000_000), nil
				},
			},
		},
	)
	resolver := Resolver{}
	resolver_init(&resolver, &interpreter)
	resolver_resolve_stmts(&resolver, stmts[:])
	if had_error {
		return
	}
	interpreter_interpret(&interpreter, stmts[:])
}

Interpreter :: struct {
	globals: ^Env,
	env:     ^Env,
	locals:  map[Expr]int,
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
	literal: Value,
}

Function :: struct {
	decl:           ^Stmt_Function,
	closure:        ^Env,
	is_initializer: bool,
}

Class :: struct {
	name:    string,
	methods: map[string]Function,
}

Value :: union {
	string,
	bool,
	f64,
	[dynamic]Value,
	Function,
	Class,
	^Instance,
}

Instance :: struct {
	class:  Class,
	fields: map[string]Value,
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
	ch := scanner_advance(s)

	switch ch {
	case '(':
		scanner_add_token(s, .Left_Paren, "(")
	case ')':
		scanner_add_token(s, .Right_Paren, ")")
	case '{':
		scanner_add_token(s, .Left_Brace, "{")
	case '}':
		scanner_add_token(s, .Right_Brace, "}")
	case ',':
		scanner_add_token(s, .Comma, ",")
	case '.':
		scanner_add_token(s, .Dot, ".")
	case '-':
		scanner_add_token(s, .Minus, "-")
	case '+':
		scanner_add_token(s, .Plus, "+")
	case ';':
		scanner_add_token(s, .Semicolon, ";")
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
		if is_alpha(ch) {
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
	scanner_add_token_with_lexeme(s, type, text)
}

scanner_add_simple_token :: proc(s: ^Scanner, kind: Token_Kind) {
	append(&s.tokens, Token{kind = kind, line = s.line})
}
scanner_add_token_with_literal :: proc(s: ^Scanner, kind: Token_Kind, literal: Value) {
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
	fmt.printf("[line %d] Error:", line)
	for msg in message {
		fmt.print(msg)
	}
	fmt.print("\n")
	had_error = true
}

error :: proc(token: ^Token, msg: string) -> Error {
	if token.kind == .EOF {
		report(token.line, " at the end. ", msg)
	} else {
		report(token.line, " at '", token.lexeme, "' ", msg)
	}
	return Error_Unexpected_Token{token = token, message = msg}
}

Expr :: union {
	^Expr_Literal,
	^Expr_Unary,
	^Expr_Binary,
	^Expr_Grouping,
	^Expr_Variable,
	^Expr_Assignment,
	^Expr_Logical,
	^Expr_Call,
	^Expr_Get,
	^Expr_Set,
	^Expr_This,
}

Expr_Call :: struct {
	callee: Expr,
	paren:  ^Token,
	args:   []Expr,
}

Expr_Get :: struct {
	object: Expr,
	name:   ^Token,
}

Expr_Set :: struct {
	object: Expr,
	name:   ^Token,
	value:  Expr,
}

Expr_This :: struct {
	keyword: ^Token,
}

Expr_Logical :: struct {
	operator: ^Token,
	left:     Expr,
	right:    Expr,
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
	value: Value,
}

Expr_Unary :: struct {
	operator: ^Token,
	right:    Expr,
}

Expr_Variable :: struct {
	name: ^Token,
}

Expr_Assignment :: struct {
	name:  ^Token,
	value: Expr,
}

Parser :: struct {
	current: int,
	tokens:  []Token,
}

Error :: union {
	Error_Unexpected_Token,
	Error_Variable_Undefined,
	Error_Incorrect_Args_Amount,
	Error_Return_Propagation,
	Error_Property_Undefined,
}

Error_Variable_Undefined :: struct {
	name: ^Token,
}

Error_Property_Undefined :: struct {
	name: ^Token,
}

Error_Incorrect_Args_Amount :: struct {
	fn:       ^Token,
	expected: int,
	received: int,
}

// Not actually an error, just a way to easily propagate returned value to the call place
Error_Return_Propagation :: struct {
	val: Value,
}


Error_Unexpected_Token :: struct {
	token:   ^Token,
	message: string,
}

parser_parse :: proc(p: ^Parser) -> (stmts: [dynamic]Stmt, err: Error) {
	stmts = make([dynamic]Stmt)
	for !parser_is_eof(p) {
		stmt := parser_decl(p)
		append(&stmts, stmt)
	}
	return stmts, nil
}

parser_from_tokens :: proc(tokens: []Token) -> Parser {
	return Parser{tokens = tokens}
}

parser_expression :: proc(p: ^Parser, allocator := context.allocator) -> (Expr, Error) {
	return parser_assignment(p, allocator)
}

parser_assignment :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	expr := parser_or(p, allocator) or_return

	if parser_match(p, {.Equal}) {
		equals := parser_prev(p)
		val := parser_assignment(p, allocator) or_return

		#partial switch e in expr {
		case ^Expr_Variable:
			assign := new(Expr_Assignment, allocator)
			assign.name = e.name
			assign.value = val
			return assign, nil
		case ^Expr_Get:
			set := new(Expr_Set, allocator)
			set.object = e.object
			set.name = e.name
			set.value = val
			return set, nil
		case:
			return nil, error(equals, "Invalid assignment target.")
		}
	}

	return expr, nil
}

parser_or :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	expr := parser_and(p, allocator) or_return

	for parser_match(p, {.Or}) {
		operator := parser_prev(p)
		right := parser_and(p, allocator) or_return
		new_expr := new(Expr_Logical, allocator)
		new_expr.left = expr
		new_expr.right = right
		new_expr.operator = operator
		expr = new_expr
	}

	return expr, nil
}

parser_and :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	expr := parser_equality(p, allocator) or_return

	for parser_match(p, {.And}) {
		operator := parser_prev(p)
		right := parser_equality(p, allocator) or_return
		new_expr := new(Expr_Logical, allocator)
		new_expr.left = expr
		new_expr.right = right
		new_expr.operator = operator
		expr = new_expr
	}

	return expr, nil
}

parser_equality :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	expr := parser_comparison(p, allocator) or_return

	for parser_match(p, {.Bang_Equal, .Equal_Equal}) {
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

parser_comparison :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
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

parser_term :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
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

parser_factor :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
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

parser_unary :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	if parser_match(p, {.Bang, .Minus}) {
		operator := parser_prev(p)
		right := parser_unary(p) or_return
		unary := new(Expr_Unary, allocator)
		unary.operator = operator
		unary.right = right
		return unary, nil
	}
	return parser_call(p, allocator)
}

parser_call :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	expr := parser_primary(p, allocator) or_return

	for {
		if parser_match(p, {.Left_Paren}) {
			expr = parser_finish_call(p, expr, allocator) or_return
		} else if parser_match(p, {.Dot}) {
			name := parser_consume(p, .Identifier, "Expect property name after '.'.") or_return
			get := new(Expr_Get, allocator)
			get.object = expr
			get.name = name
			expr = get
		} else {
			break
		}
	}
	return expr, nil
}

parser_finish_call :: proc(
	p: ^Parser,
	callee: Expr,
	allocator := context.allocator,
) -> (
	expr: Expr,
	err: Error,
) {
	args := make([dynamic]Expr)
	defer if err != nil {
		delete(args)
	}

	if !parser_check(p, .Right_Paren) {
		expr = parser_expression(p) or_return
		append(&args, expr)

		for parser_match(p, {.Comma}) {
			if len(args) >= 255 {
				_ = error(parser_peek(p), "Can't have more than 255 arguments.")
			}
			expr = parser_expression(p) or_return
			append(&args, expr)
		}
	}

	paren := parser_consume(p, .Right_Paren, "Expect ')' after arguments.") or_return

	call := new(Expr_Call, allocator)
	call.paren = paren
	call.args = args[:]
	call.callee = callee

	return call, nil
}

parser_primary :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
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

	if parser_match(p, {.This}) {
		this := new(Expr_This, allocator)
		this.keyword = parser_prev(p)
		return this, nil
	}

	if parser_match(p, {.Identifier}) {
		expr := new(Expr_Variable, allocator)
		expr.name = parser_prev(p)
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

parser_consume :: proc(p: ^Parser, kind: Token_Kind, msg: string) -> (^Token, Error) {
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

interpreter_expr_to_value :: proc(
	i: ^Interpreter,
	expr: Expr,
	allocator := context.allocator,
) -> (
	v: Value,
	err: Error,
) {
	switch v in expr {
	case ^Expr_Grouping:
		return interpreter_expr_to_value(i, v.expression, allocator)
	case ^Expr_Literal:
		return v.value, nil
	case ^Expr_Unary:
		right := interpreter_expr_to_value(i, v.right, allocator) or_return

		#partial switch v.operator.kind {
		case .Minus:
			num := right.(f64)
			return -num, nil
		case .Bang:
			return !value_is_truthy(right), nil
		}
		return nil, nil // unreachebale
	case ^Expr_Binary:
		left := interpreter_expr_to_value(i, v.left, allocator) or_return
		right := interpreter_expr_to_value(i, v.right, allocator) or_return
		#partial switch v.operator.kind {
		case .Minus:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) - right.(f64), nil
		case .Slash:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) / right.(f64), nil
		case .Star:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) * right.(f64), nil
		case .Plus:
			l_num, l_num_ok := left.(f64)
			r_num, r_num_ok := right.(f64)
			if l_num_ok && r_num_ok {
				return l_num + r_num, nil
			}
			l_str, l_str_ok := left.(string)
			r_str, r_str_ok := right.(string)
			if l_str_ok && r_str_ok {
				res := strings.concatenate({l_str, r_str}, allocator)
				return res, nil
			}
			return nil, Error_Unexpected_Token {
				token = v.operator,
				message = "Operands must both be numbers or strings",
			}
		case .Greater:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) > right.(f64), nil
		case .Greater_Equal:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) >= right.(f64), nil
		case .Less:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) < right.(f64), nil
		case .Less_Equal:
			operands_are_numbers(v.operator, left, right) or_return
			return left.(f64) <= right.(f64), nil
		case .Bang_Equal:
			return !values_are_equal(left, right), nil
		case .Equal_Equal:
			return values_are_equal(left, right), nil
		}
	case ^Expr_Variable:
		val, ok := interpreter_look_up_variable(i, v.name, v)
		if !ok {
			return nil, Error_Variable_Undefined{name = v.name}
		}
		return val, nil
	case ^Expr_Assignment:
		val := interpreter_expr_to_value(i, v.value, allocator) or_return
		distance, has_distance := i.locals[v]

		if has_distance {
			env_assign_at(i.env, distance, v.name.lexeme, val)
		} else {
			env_assign(i.globals, v.name, val) or_return
		}
		return val, nil
	case ^Expr_Logical:
		left := interpreter_expr_to_value(i, v.left, allocator) or_return

		is_truthy := value_is_truthy(left)
		if v.operator.kind == .Or {
			if is_truthy do return left, nil
		} else {
			if !is_truthy do return left, nil
		}

		return interpreter_expr_to_value(i, v.right, allocator)
	case ^Expr_Call:
		callee := interpreter_expr_to_value(i, v.callee, allocator) or_return
		#partial switch &c in callee {
		case Function:
			args := make([dynamic]Value)
			defer {
				delete(args)
			}

			for arg in v.args {
				val := interpreter_expr_to_value(i, arg, allocator) or_return
				append(&args, val)
			}

			if len(c.decl.params) != len(args) {
				return nil, Error_Incorrect_Args_Amount {
					fn = v.paren,
					expected = len(c.decl.params),
					received = len(args),
				}
			}
			return c.decl.call(i, &c, args[:], allocator)
		case Class:
			args := make([dynamic]Value)
			defer {
				delete(args)
			}

			for arg in v.args {
				val := interpreter_expr_to_value(i, arg, allocator) or_return
				append(&args, val)
			}
			if len(args) != 0 {
				return nil, Error_Incorrect_Args_Amount {
					fn = v.paren,
					expected = 0,
					received = len(args),
				}
			}
			instance := new(Instance, allocator)
			instance.class = c
			instance.fields = make(map[string]Value, allocator)

			init, has_init := c.methods["init"]
			if has_init {
				fn := function_bind(&init, instance, allocator)
				if len(fn.decl.params) != len(args) {
					return nil, Error_Incorrect_Args_Amount {
						fn = v.paren,
						expected = len(fn.decl.params),
						received = len(args),
					}
				}
				interpreter_function_call(i, &fn, args[:], allocator)
			}
			return instance, nil
		case:
			return nil, Error_Unexpected_Token {
				token = v.paren,
				message = "Can only call functions and classes",
			}
		}
	case ^Expr_Get:
		obj := interpreter_expr_to_value(i, v.object, allocator) or_return
		if instance, is_instance := obj.(^Instance); is_instance {
			return instance_get(instance, v.name, allocator)
		}

		return nil, Error_Unexpected_Token{v.name, "Only instances have properties."}
	case ^Expr_Set:
		object := interpreter_expr_to_value(i, v.object, allocator) or_return

		#partial switch &obj in object {
		case ^Instance:
			val := interpreter_expr_to_value(i, v.value, allocator) or_return
			instance_set(obj, v.name, val)
			return val, nil
		case:
			return nil, Error_Unexpected_Token{v.name, "Only instances have fields."}
		}
	case ^Expr_This:
		val, ok := interpreter_look_up_variable(i, v.keyword, v)
		if !ok {
			return nil, Error_Variable_Undefined{name = v.keyword}
		}
		return val, nil
	}
	return nil, nil
}

//`false` and `nil` are falsy, all the other values are truthy
value_is_truthy :: proc(v: Value) -> bool {
	if v == nil do return false

	boolean, ok := v.(bool)
	if ok do return boolean

	return true
}

values_are_equal :: proc(left, right: Value) -> bool {
	switch l in left {
	case bool:
		r := right.(bool) or_return
		return l == r
	case string:
		r := right.(string) or_return
		return l == r
	case f64:
		r := right.(f64) or_return
		return l == r
	case [dynamic]Value:
		r := right.([dynamic]Value) or_return
		return(
			len(r) == len(l) &&
			((transmute(runtime.Raw_Dynamic_Array)l).data ==
					(transmute(runtime.Raw_Dynamic_Array)r).data) \
		)
	case Function:
		r := right.(Function) or_return
		return l.decl == r.decl
	case Class:
		r := right.(Class) or_return
		return r.name == l.name
	case ^Instance:
		r := right.(^Instance) or_return
		return r == l
	case nil:
		return right == nil
	}
	return false
}

operand_is_number :: proc(tkn: ^Token, operand: Value) -> Error {
	_, is_num := operand.(f64)
	if is_num {
		return nil
	} else {
		return Error_Unexpected_Token{token = tkn, message = "Operand must be a number."}
	}
}
operands_are_numbers :: proc(tkn: ^Token, left, right: Value) -> Error {
	_, left_num := left.(f64)
	_, right_num := right.(f64)
	if left_num && right_num {
		return nil
	} else {
		return Error_Unexpected_Token{token = tkn, message = "Operands must be numbers."}
	}
}

interpreter_interpret :: proc(i: ^Interpreter, stmts: []Stmt) {
	for s in stmts {
		err := interpreter_stmt_execute(i, s)
		if err != nil {
			runtime_error(err)
			break
		}
	}
}

runtime_error :: proc(err: Error) {
	if err == nil do return
	switch v in err {
	case Error_Unexpected_Token:
		fmt.eprintfln("[line %d]: %s", v.token.line, v.message)
	case Error_Variable_Undefined:
		fmt.eprintfln("Undefined variable '%s' at line %d.", v.name.lexeme, v.name.line)
	case Error_Incorrect_Args_Amount:
		fmt.eprintfln(
			"[line %d]: Expected %d arguments, received %d instead.",
			v.fn.line,
			v.expected,
			v.received,
		)
	case Error_Property_Undefined:
		fmt.eprintfln("Undefined property \"%s\".", v.name.lexeme)
	case Error_Return_Propagation: // should never happen as it is return mechanism
	}
	had_runtime_error = true
}

Stmt :: union {
	^Stmt_Print,
	^Stmt_Expr,
	^Stmt_Var,
	^Stmt_Block,
	^Stmt_If,
	^Stmt_While,
	^Stmt_Function,
	^Stmt_Return,
	^Stmt_Class,
}

Stmt_While :: struct {
	condition: Expr,
	body:      Stmt,
}

Stmt_Print :: struct {
	expr: Expr,
}

Stmt_Expr :: struct {
	expr: Expr,
}

Stmt_Var :: struct {
	name:        ^Token,
	initializer: Expr,
}

Stmt_Block :: struct {
	statements: []Stmt,
}

Stmt_If :: struct {
	condition:   Expr,
	branch_then: Stmt,
	branch_else: Stmt,
}

Stmt_Class :: struct {
	name:    ^Token,
	methods: []^Stmt_Function,
}

Stmt_Function :: struct {
	name:   ^Token,
	params: []^Token,
	body:   []Stmt,
	call:   proc(
		i: ^Interpreter,
		fn: ^Function,
		args: []Value,
		allocator := context.allocator,
	) -> (
		Value,
		Error,
	),
}

Stmt_Return :: struct {
	keyword: ^Token,
	value:   Expr,
}

interpreter_execute_block :: proc(
	i: ^Interpreter,
	stmts: []Stmt,
	new_env: ^Env,
	allocator := context.allocator,
) -> Error {
	prev_env := i.env
	i.env = new_env
	defer {
		i.env = prev_env
	}

	for stmt in stmts {
		interpreter_stmt_execute(i, stmt, allocator) or_return
	}
	return nil
}

parser_stmt :: proc(p: ^Parser, allocator := context.allocator) -> (Stmt, Error) {
	if parser_match(p, {.For}) {
		return parser_stmt_for(p, allocator)
	}
	if parser_match(p, {.If}) {
		return parser_stmt_if(p, allocator)
	}
	if parser_match(p, {.Print}) {
		return parser_stmt_print(p, allocator)
	}
	if parser_match(p, {.Return}) {
		return parser_stmt_return(p, allocator)
	}
	if parser_match(p, {.While}) {
		return parser_stmt_while(p, allocator)
	}
	if parser_match(p, {.Left_Brace}) {
		return parser_stmt_block(p, allocator)
	}
	return parser_stmt_expression(p, allocator)
}

parser_stmt_for :: proc(p: ^Parser, allocator := context.allocator) -> (stmt: Stmt, err: Error) {
	parser_consume(p, .Left_Paren, "Expect '(' after 'for'.") or_return
	initializer: Stmt
	if parser_match(p, {.Semicolon}) {
		initializer = nil
	} else if parser_match(p, {.Var}) {
		initializer = parser_stmt_var_decl(p, allocator) or_return
	} else {
		initializer = parser_stmt_expression(p, allocator) or_return
	}

	condition: Expr
	if !parser_check(p, .Semicolon) {
		condition = parser_expression(p, allocator) or_return
	}
	parser_consume(p, .Semicolon, "Expect ';' after loop condition.") or_return

	increment: Expr
	if !parser_check(p, .Right_Paren) {
		increment = parser_expression(p, allocator) or_return
	}
	parser_consume(p, .Right_Paren, "Expect ')' after for clause.") or_return

	body := parser_stmt(p, allocator) or_return
	if increment != nil {
		expr := new(Stmt_Expr, allocator)
		expr.expr = increment
		new_body := new(Stmt_Block, allocator)
		statements := make([]Stmt, 2, allocator)
		statements[0] = body
		statements[1] = expr
		new_body.statements = statements
		body = new_body
	}

	if condition == nil {
		new_condition := new(Expr_Literal, allocator)
		new_condition.value = true
		condition = new_condition
	}

	while := new(Stmt_While, allocator)
	while.condition = condition
	while.body = body
	body = while

	if initializer != nil {
		new_body := new(Stmt_Block, allocator)
		statements := make([]Stmt, 2, allocator)
		statements[0] = initializer
		statements[1] = body
		new_body.statements = statements
		body = new_body
	}

	return body, nil
}

parser_stmt_return :: proc(
	p: ^Parser,
	allocator := context.allocator,
) -> (
	stmt: Stmt,
	err: Error,
) {
	keyword := parser_prev(p)
	val: Expr

	if !parser_check(p, .Semicolon) {
		val = parser_expression(p, allocator) or_return
	}
	parser_consume(p, .Semicolon, "Expect ';' after return value.") or_return
	ret := new(Stmt_Return, allocator)
	ret.value = val
	ret.keyword = keyword
	return ret, nil
}

parser_stmt_while :: proc(p: ^Parser, allocator := context.allocator) -> (stmt: Stmt, err: Error) {
	parser_consume(p, .Left_Paren, "Expect '(' after 'while'.") or_return
	condition := parser_expression(p, allocator) or_return
	parser_consume(p, .Right_Paren, "Expect ')' after condition.") or_return
	body := parser_stmt(p, allocator) or_return

	while_ := new(Stmt_While, allocator)
	while_.body = body
	while_.condition = condition
	return while_, nil
}

parser_stmt_if :: proc(p: ^Parser, allocator := context.allocator) -> (stmt: Stmt, err: Error) {
	parser_consume(p, .Left_Paren, "Expect '(' after 'if'.") or_return
	cond := parser_expression(p, allocator) or_return
	parser_consume(p, .Right_Paren, "Expect ')' after if condition.") or_return

	branch_then := parser_stmt(p, allocator) or_return
	branch_else: Stmt
	if parser_match(p, {.Else}) {
		branch_else = parser_stmt(p, allocator) or_return
	}
	if_ := new(Stmt_If, allocator)
	if_.condition = cond
	if_.branch_then = branch_then
	if_.branch_else = branch_else
	return if_, nil
}

parser_decl :: proc(p: ^Parser, allocator := context.allocator) -> Stmt {
	if parser_match(p, {.Class}) {
		class, class_err := parser_stmt_class(p, allocator)
		if class_err != nil {
			parser_sync(p)
			return nil
		}
		return class
	}
	if parser_match(p, {.Fun}) {
		fn, err := parser_stmt_function(p, false, allocator)
		if err != nil {
			parser_sync(p)
			return nil
		}
		return fn
	}
	if parser_match(p, {.Var}) {
		var, err := parser_stmt_var_decl(p, allocator)
		if err != nil {
			parser_sync(p)
			return nil
		}
		return var
	}
	stmt, err := parser_stmt(p, allocator)
	if err != nil {
		parser_sync(p)
		return nil
	}
	return stmt
}

parser_stmt_function :: proc(
	p: ^Parser,
	is_method := false,
	allocator := context.allocator,
) -> (
	stmt: ^Stmt_Function,
	err: Error,
) {
	name := parser_consume(
		p,
		.Identifier,
		is_method ? "Expect method name." : "Expect function name.",
	) or_return

	parser_consume(
		p,
		.Left_Paren,
		is_method ? "Expect '(' after method name." : "Expect '(' after function name.",
	) or_return
	params := make([dynamic]^Token, allocator)
	defer if err != nil {
		delete(params)
	}

	if !parser_check(p, .Right_Paren) {
		tkn := parser_consume(p, .Identifier, "Expect parameter name.") or_return
		append(&params, tkn)

		for parser_match(p, {.Comma}) {
			if len(params) >= 255 {
				error(parser_peek(p), "Can't have more than 255 parameters.")
			}
			tkn := parser_consume(p, .Identifier, "Expect parameter name.") or_return
			append(&params, tkn)
		}
	}
	parser_consume(p, .Right_Paren, "Expect ')' after parameters.") or_return
	parser_consume(p, .Left_Brace, "Expect '{' before body.") or_return
	block := parser_block(p, allocator) or_return
	fn := new(Stmt_Function, allocator)
	fn.params = params[:]
	fn.body = block
	fn.name = name
	fn.call = interpreter_function_call
	return fn, nil
}


parser_stmt_var_decl :: proc(
	p: ^Parser,
	allocator := context.allocator,
) -> (
	stmt: ^Stmt_Var,
	err: Error,
) {
	name := parser_consume(p, .Identifier, "Expect variable name.") or_return
	init: Expr
	if parser_match(p, {.Equal}) {
		init = parser_expression(p) or_return
	}
	parser_consume(p, .Semicolon, "Expect ';' after variable declaration.") or_return
	decl := new(Stmt_Var, allocator)
	decl.name = name
	decl.initializer = init
	return decl, nil
}

parser_stmt_class :: proc(
	p: ^Parser,
	allocator := context.allocator,
) -> (
	stmt: ^Stmt_Class,
	err: Error,
) {
	name := parser_consume(p, .Identifier, "Expect class name.") or_return
	parser_consume(p, .Left_Brace, "Expect '{' before class body.") or_return

	methods := make([dynamic]^Stmt_Function, allocator)
	defer if err != nil {
		delete(methods)
	}

	for !parser_check(p, .Right_Brace) && !parser_is_eof(p) {
		fn := parser_stmt_function(p, true, allocator) or_return
		append(&methods, fn)
	}

	parser_consume(p, .Right_Brace, "Expect '}' after class body.") or_return

	class := new(Stmt_Class, allocator)
	class.methods = methods[:]
	class.name = name
	return class, nil
}

parser_stmt_print :: proc(p: ^Parser, allocator := context.allocator) -> (s: Stmt, err: Error) {
	val := parser_expression(p) or_return
	parser_consume(p, .Semicolon, "Expect ';' after value.") or_return
	stmt := new(Stmt_Print, allocator)
	stmt.expr = val
	return stmt, nil
}

parser_stmt_expression :: proc(
	p: ^Parser,
	allocator := context.allocator,
) -> (
	s: Stmt,
	err: Error,
) {
	val := parser_expression(p) or_return
	parser_consume(p, .Semicolon, "Expect ';' after value.") or_return
	stmt := new(Stmt_Expr, allocator)
	stmt.expr = val
	return stmt, nil
}

parser_stmt_block :: proc(p: ^Parser, allocator := context.allocator) -> (stmt: Stmt, err: Error) {
	block_stmts := parser_block(p, allocator) or_return
	block := new(Stmt_Block, allocator)
	block.statements = block_stmts
	return block, nil
}

parser_block :: proc(p: ^Parser, allocator := context.allocator) -> ([]Stmt, Error) {
	stmts := make([dynamic]Stmt)

	for !parser_check(p, .Right_Brace) && !parser_is_eof(p) {
		append(&stmts, parser_decl(p, allocator))
	}

	if _, err := parser_consume(p, .Right_Brace, "Expect '}' after block"); err != nil {
		delete(stmts)
		return {}, err
	}
	return stmts[:], nil
}

interpreter_stmt_execute :: proc(
	i: ^Interpreter,
	stmt: Stmt,
	allocator := context.allocator,
) -> Error {
	switch v in stmt {
	case (^Stmt_Expr):
		interpreter_expr_to_value(i, v.expr, allocator) or_return
	case (^Stmt_Print):
		val := interpreter_expr_to_value(i, v.expr, allocator) or_return
		str := value_to_string(val)
		fmt.println(str)
	case (^Stmt_Var):
		val: Value
		if v.initializer != nil {
			val = interpreter_expr_to_value(i, v.initializer, allocator) or_return
		}
		env_define(i.env, v.name.lexeme, val)
	case (^Stmt_Block):
		new_env := new(Env, allocator)
		new_env.enclosing = i.env
		new_env.values = make(map[string]Value, allocator)
		interpreter_execute_block(i, v.statements, new_env, allocator) or_return
	case (^Stmt_If):
		val := interpreter_expr_to_value(i, v.condition, allocator) or_return
		if value_is_truthy(val) {
			interpreter_stmt_execute(i, v.branch_then, allocator) or_return
		} else if v.branch_else != nil {
			interpreter_stmt_execute(i, v.branch_else, allocator) or_return
		}
	case (^Stmt_While):
		for {
			val := interpreter_expr_to_value(i, v.condition, allocator) or_return
			if !value_is_truthy(val) {
				break
			}
			interpreter_stmt_execute(i, v.body, allocator) or_return
		}
	case (^Stmt_Function):
		fn := Function {
			decl    = v,
			closure = i.env,
		}
		env_define(i.env, v.name.lexeme, fn)
	case (^Stmt_Return):
		val: Value
		if v.value != nil {
			val = interpreter_expr_to_value(i, v.value, allocator) or_return
		}
		return Error_Return_Propagation{val}
	case ^Stmt_Class:
		env_define(i.env, v.name.lexeme, nil)

		methods := make(map[string]Function, allocator)
		for method in v.methods {
			fn := Function {
				decl           = method,
				closure        = i.env,
				is_initializer = method.name.lexeme == "init",
			}
			methods[method.name.lexeme] = fn
		}

		class := Class {
			name    = v.name.lexeme,
			methods = methods,
		}
		env_assign(i.env, v.name, class)
	}
	return nil
}

Env :: struct {
	enclosing: ^Env,
	values:    map[string]Value,
}

env_init :: proc(enclosing: ^Env = nil) -> Env {
	return {values = make(map[string]Value), enclosing = enclosing}
}

env_define :: #force_inline proc(env: ^Env, name: string, val: Value) {
	env.values[name] = val
}

env_get :: proc(env: ^Env, name: string) -> (val: Value, ok: bool) {
	val, ok = env.values[name]
	if ok {
		return val, ok
	}
	if env.enclosing == nil {
		return nil, false
	}
	return env_get(env.enclosing, name)
}

env_assign :: proc(env: ^Env, name: ^Token, val: Value) -> Error {
	if _, has_var := env.values[name.lexeme]; has_var {
		env.values[name.lexeme] = val
		return nil
	}
	if env.enclosing != nil {
		return env_assign(env.enclosing, name, val)
	}
	return Error_Variable_Undefined{name = name}
}

value_to_string :: proc(val: Value, allocator := context.allocator) -> string {
	switch v in val {
	case string:
		return v
	case nil, f64, bool, [dynamic]Value:
		return fmt.aprintf("%#v", v, allocator = allocator)
	case Function:
		if v.decl.call == interpreter_function_call {
			return fmt.aprintf("<fn %s>", v.decl.name.lexeme)
		} else {
			return fmt.aprintf("<native fn %s>", v.decl.name.lexeme)
		}
	case Class:
		return v.name
	case ^Instance:
		return fmt.aprintf("%s instance", v.class.name)
	}
	return ""
}

interpreter_function_call :: proc(
	i: ^Interpreter,
	fn: ^Function,
	args: []Value,
	allocator := context.allocator,
) -> (
	Value,
	Error,
) {
	fn_env := new(Env, allocator)
	fn_env.enclosing = fn.closure

	for i in 0 ..< len(args) {
		env_define(fn_env, fn.decl.params[i].lexeme, args[i])
	}
	possible_err := interpreter_execute_block(i, fn.decl.body, fn_env, allocator)
	result, is_result := possible_err.(Error_Return_Propagation)
	if is_result {
		if fn.is_initializer {
			this, _ := env_get_at(fn.closure, 0, "this")
			return this, nil
		}
		return result.val, nil
	}

	if fn.is_initializer {
		this, _ := env_get_at(fn.closure, 0, "this")
		return this, nil
	}
	return nil, possible_err
}

Resolver :: struct {
	scopes:           [dynamic]map[string]bool,
	interpreter:      ^Interpreter,
	current_function: Resolver_Function_Type,
	current_class:    Resolver_Class_Type,
}

Resolver_Function_Type :: enum u8 {
	None,
	Function,
	Method,
	Initializer,
}

Resolver_Class_Type :: enum u8 {
	None,
	Class,
}

resolver_init :: proc(
	r: ^Resolver,
	interpreter: ^Interpreter = nil,
	allocator := context.allocator,
) {
	r.scopes = make([dynamic]map[string]bool, allocator)
	r.interpreter = interpreter
}

resolver_resolve_expr :: proc(
	r: ^Resolver,
	expr: Expr,
	allocator := context.allocator,
) -> (
	err: Error,
) {
	switch e in expr {
	case ^Expr_Variable:
		if len(r.scopes) != 0 && r.scopes[len(r.scopes) - 1][e.name.lexeme] == false {
			return error(e.name, "Can't read local variable in it's own initializer.")
		}
		resolver_resolve_local(r, e, e.name, allocator) or_return
	case ^Expr_Assignment:
		resolver_resolve_expr(r, e.value, allocator) or_return
		resolver_resolve_local(r, e, e.name, allocator) or_return
	case ^Expr_Binary:
		resolver_resolve_expr(r, e.left, allocator) or_return
		resolver_resolve_expr(r, e.right, allocator) or_return
	case ^Expr_Call:
		resolver_resolve_expr(r, e.callee, allocator) or_return
		for arg in e.args {
			resolver_resolve_expr(r, arg, allocator) or_return
		}
	case ^Expr_Grouping:
		resolver_resolve_expr(r, e.expression, allocator) or_return
	case ^Expr_Literal:
		return nil
	case ^Expr_Logical:
		resolver_resolve_expr(r, e.left, allocator) or_return
		resolver_resolve_expr(r, e.right, allocator) or_return
	case ^Expr_Unary:
		resolver_resolve_expr(r, e.right, allocator) or_return
	case ^Expr_Get:
		resolver_resolve_expr(r, e.object, allocator) or_return
	case ^Expr_Set:
		resolver_resolve_expr(r, e.value, allocator) or_return
		resolver_resolve_expr(r, e.object, allocator) or_return
	case ^Expr_This:
		if r.current_class == .None {
			error(e.keyword, "Can't use 'this' outside of a class.")
			return nil
		}
		resolver_resolve_local(r, e, e.keyword, allocator) or_return
	}
	return nil
}

resolver_resolve_local :: proc(
	r: ^Resolver,
	expr: Expr,
	name: ^Token,
	allocator := context.allocator,
) -> (
	err: Error,
) {
	for i := len(r.scopes) - 1; i >= 0; i -= 1 {
		scope := r.scopes[i]
		if _, has_key := scope[name.lexeme]; has_key {
			interpreter_resolve(r.interpreter, expr, len(r.scopes) - 1 - i)
			return nil
		}
	}
	return nil
}

resolver_resolve_stmt :: proc(
	r: ^Resolver,
	stmt: Stmt,
	allocator := context.allocator,
) -> (
	err: Error,
) {
	switch s in stmt {
	case ^Stmt_Block:
		resolver_scope_begin(r, allocator)
		for st in s.statements {
			resolver_resolve_stmt(r, st) or_return
		}
	case ^Stmt_Var:
		resolver_declare(r, s.name)
		if s.initializer != nil {
			resolver_resolve_expr(r, s.initializer) or_return
		}
		resolver_define(r, s.name)
	case ^Stmt_Function:
		resolver_declare(r, s.name)
		resolver_define(r, s.name)

		resolver_resolve_function(r, s, .Function, allocator) or_return
	case ^Stmt_Expr:
		resolver_resolve_expr(r, s.expr) or_return
	case ^Stmt_If:
		resolver_resolve_expr(r, s.condition) or_return
		resolver_resolve_stmt(r, s.branch_then) or_return
		if s.branch_else != nil do resolver_resolve_stmt(r, s.branch_else) or_return
	case ^Stmt_Print:
		resolver_resolve_expr(r, s.expr) or_return
	case ^Stmt_Return:
		if r.current_function == .None {
			error(s.keyword, "Can't return from top level code.")
		}

		if s.value != nil {
			if r.current_function == .Initializer {
				error(s.keyword, "Can't return a value from an initializer")
			}
			resolver_resolve_expr(r, s.value) or_return
		}
	case ^Stmt_While:
		resolver_resolve_expr(r, s.condition) or_return
		resolver_resolve_stmt(r, s.body) or_return
	case ^Stmt_Class:
		enclosing_class := r.current_class
		r.current_class = .Class
		defer r.current_class = enclosing_class

		resolver_declare(r, s.name)
		resolver_define(r, s.name)

		resolver_scope_begin(r, allocator)
		r.scopes[len(r.scopes) - 1]["this"] = true
		defer resolver_scope_end(r)

		for method in s.methods {
			fn_type := Resolver_Function_Type.Method
			if method.name.lexeme == "init" {
				fn_type = .Initializer
			}
			resolver_resolve_function(r, method, fn_type, allocator) or_return
		}
	}
	return nil
}

resolver_resolve_stmts :: proc(
	r: ^Resolver,
	stmts: []Stmt,
	allocator := context.allocator,
) -> (
	err: Error,
) {
	for stmt in stmts {
		resolver_resolve_stmt(r, stmt, allocator) or_return
	}
	return nil
}

resolver_scope_begin :: proc(r: ^Resolver, allocator := context.allocator) {
	new_scope := make(map[string]bool, allocator)
	append(&r.scopes, new_scope)
}
resolver_scope_end :: proc(r: ^Resolver) {
	last_scope := pop(&r.scopes)
	delete(last_scope)
}

resolver_declare :: proc(r: ^Resolver, name: ^Token) {
	if len(r.scopes) == 0 do return
	scope := &r.scopes[len(r.scopes) - 1]
	if _, in_scope := scope[name.lexeme]; in_scope {
		error(name, "Already have a variable with this name in the scope.")
	}
	scope[name.lexeme] = false
}
resolver_define :: proc(r: ^Resolver, name: ^Token) {
	if len(r.scopes) == 0 do return
	scope := r.scopes[len(r.scopes) - 1]
	scope[name.lexeme] = true
}

resolver_resolve_function :: proc(
	r: ^Resolver,
	fn: ^Stmt_Function,
	fn_type: Resolver_Function_Type,
	allocator := context.allocator,
) -> (
	err: Error,
) {
	enclosing_fn := r.current_function
	r.current_function = fn_type
	defer r.current_function = enclosing_fn

	resolver_scope_begin(r, allocator)
	defer resolver_scope_end(r)

	for param in fn.params {
		resolver_declare(r, param)
		resolver_define(r, param)
	}

	for stmt in fn.body {
		resolver_resolve_stmt(r, stmt, allocator) or_return
	}
	return nil
}

interpreter_resolve :: proc(i: ^Interpreter, expr: Expr, depth: int) {
	i.locals[expr] = depth
}

interpreter_look_up_variable :: proc(i: ^Interpreter, name: ^Token, expr: Expr) -> (Value, bool) {
	distance, has_distance := i.locals[expr]

	if has_distance {
		return env_get_at(i.env, distance, name.lexeme)
	} else {
		return i.globals.values[name.lexeme]
	}
	return nil, false
}

env_get_at :: proc(env: ^Env, distance: int, name: string) -> (Value, bool) {
	ancestor := env_ancestor(env, distance)
	if ancestor == nil do return nil, false
	return ancestor.values[name]
}

env_assign_at :: proc(env: ^Env, distance: int, name: string, value: Value) {
	ancestor := env_ancestor(env, distance)
	ancestor.values[name] = value
}

env_ancestor :: proc(env: ^Env, distance: int) -> ^Env {
	e := env
	for i := 0; i < distance; i += 1 {
		if e == nil do return e
		e = e.enclosing
	}
	return e
}

instance_get :: proc(
	i: ^Instance,
	name: ^Token,
	allocator := context.allocator,
) -> (
	Value,
	Error,
) {
	property, has_property := i.fields[name.lexeme]
	if has_property {
		return property, nil
	}
	method, has_method := i.class.methods[name.lexeme]
	if has_method {
		return function_bind(&method, i, allocator), nil
	}
	return nil, Error_Property_Undefined{name}
}

instance_set :: proc(i: ^Instance, name: ^Token, val: Value) {
	i.fields[name.lexeme] = val
}

function_bind :: proc(fn: ^Function, i: ^Instance, allocator := context.allocator) -> Function {
	new_env := new(Env, allocator)
	new_env.enclosing = fn.closure
	env_define(new_env, "this", i)
	return {closure = new_env, decl = fn.decl, is_initializer = fn.is_initializer}
}
