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
	expr, err := parser_parse(&p)
	if err != nil {
		return
	}
	global_env := env_init()
	env_define(
		&global_env,
		"clock",
		Function {
			decl = &Stmt_Function {
				name = &Token{lexeme = "clock", kind = .Identifier},
				call = proc(
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
	stmt_interpret(expr[:], &global_env)
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
	decl:    ^Stmt_Function,
	closure: ^Env,
}

Value :: union {
	string,
	bool,
	f64,
	Object,
	[dynamic]Value,
	Function,
}

Object_Key :: union #no_nil {
	string,
	bool,
	f64,
}
Object :: map[Object_Key]Value

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
	if type == .Identifier {
		scanner_add_token_with_lexeme(s, type, text)
	} else {
		scanner_add_token(s, type)
	}
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
	return Parse_Error_Unexpected_Token{token = token, message = msg}
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
	^Expr_Lambda,
}

Expr_Lambda :: struct {
	fn: ^Stmt_Function,
}

Expr_Call :: struct {
	callee: Expr,
	paren:  ^Token,
	args:   []Expr,
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
	Parse_Error_Unexpected_Token,
	Error_Variable_Undefined,
	Error_Incorrect_Args_Amount,
	Error_Return_Propagation,
}

Error_Variable_Undefined :: struct {
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


Parse_Error_Unexpected_Token :: struct {
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

		var, is_var := expr.(^Expr_Variable)
		if is_var {
			name := var.name
			assign := new(Expr_Assignment, allocator)
			assign.name = name
			assign.value = val
			return assign, nil
		}

		return nil, error(equals, "Invalid assignment target.")
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

parser_lambda :: proc(p: ^Parser, allocator := context.allocator) -> (e: Expr, err: Error) {
	parser_consume(p, .Left_Paren, "Expect '(' after 'fun' keyword name.") or_return
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
	lambda := new(Expr_Lambda, allocator)
	fn := new(Stmt_Function, allocator)
	fn.params = params[:]
	fn.body = block
	fn.call = function_call
	lambda.fn = fn
	return lambda, nil
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

	if parser_match(p, {.Fun}) {
		return parser_lambda(p, allocator)
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

expr_to_value :: proc(
	expr: Expr,
	env: ^Env,
	allocator := context.allocator,
) -> (
	v: Value,
	err: Error,
) {
	switch v in expr {
	case (^Expr_Grouping):
		return expr_to_value(v.expression, env, allocator)
	case (^Expr_Literal):
		return v.value, nil
	case (^Expr_Unary):
		right := expr_to_value(v.right, env, allocator) or_return

		#partial switch v.operator.kind {
		case .Minus:
			num := right.(f64)
			return -num, nil
		case .Bang:
			return !value_is_truthy(right), nil
		}
		return nil, nil // unreachebale
	case (^Expr_Binary):
		left := expr_to_value(v.left, env, allocator) or_return
		right := expr_to_value(v.right, env, allocator) or_return
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
			return nil, Parse_Error_Unexpected_Token {
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
	case (^Expr_Variable):
		val, ok := env_get(env, v.name.lexeme)
		if !ok {
			return nil, Error_Variable_Undefined{name = v.name}
		}
		return val, nil
	case (^Expr_Assignment):
		val := expr_to_value(v.value, env) or_return
		env_assign(env, v.name, val) or_return
		return val, nil
	case (^Expr_Logical):
		left := expr_to_value(v.left, env) or_return

		is_truthy := value_is_truthy(left)
		if v.operator.kind == .Or {
			if is_truthy do return left, nil
		} else {
			if !is_truthy do return left, nil
		}

		return expr_to_value(v.right, env)
	case (^Expr_Call):
		callee := expr_to_value(v.callee, env) or_return
		fn, is_fn := callee.(Function)
		if !is_fn {
			return nil, Parse_Error_Unexpected_Token {
				token = v.paren,
				message = "Can only call functions and classes",
			}
		}
		args := make([dynamic]Value)
		defer {
			delete(args)
		}

		for arg in v.args {
			val := expr_to_value(arg, env) or_return
			append(&args, val)
		}

		if len(fn.decl.params) != len(args) {
			return nil, Error_Incorrect_Args_Amount {
				fn = v.paren,
				expected = len(fn.decl.params),
				received = len(args),
			}
		}
		return fn.decl.call(&fn, args[:], allocator)
	case (^Expr_Lambda):
		fn := Function{}
		fn.decl = v.fn
		fn.closure = env
		return fn, nil
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
	case Object:
		r := right.(Object) or_return
		return (transmute(runtime.Raw_Map)l).data == (transmute(runtime.Raw_Map)r).data
	case [dynamic]Value:
		r := right.([dynamic]Value) or_return
		return(
			len(r) == len(l) &&
			((transmute(runtime.Raw_Dynamic_Array)l).data ==
					(transmute(runtime.Raw_Dynamic_Array)r).data) \
		)
	case Function:
		return false
	case nil:
		if right == nil do return true
		return false
	}
	return false
}

operand_is_number :: proc(tkn: ^Token, operand: Value) -> Error {
	_, is_num := operand.(f64)
	if is_num {
		return nil
	} else {
		return Parse_Error_Unexpected_Token{token = tkn, message = "Operand must be a number."}
	}
}
operands_are_numbers :: proc(tkn: ^Token, left, right: Value) -> Error {
	_, left_num := left.(f64)
	_, right_num := right.(f64)
	if left_num && right_num {
		return nil
	} else {
		return Parse_Error_Unexpected_Token{token = tkn, message = "Operands must be numbers."}
	}
}

stmt_interpret :: proc(stmts: []Stmt, env: ^Env) {
	for s in stmts {
		err := stmt_execute(s, env)
		if err != nil {
			runtime_error(err)
			break
		}
	}
}

runtime_error :: proc(err: Error) {
	if err == nil do return
	switch v in err {
	case Parse_Error_Unexpected_Token:
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

Stmt_Function :: struct {
	name:   ^Token,
	params: []^Token,
	body:   []Stmt,
	call:   proc(fn: ^Function, args: []Value, allocator := context.allocator) -> (Value, Error),
}

Stmt_Return :: struct {
	keyword: ^Token,
	value:   Expr,
}

env_execute_block :: proc(
	outer_env: ^Env,
	stmts: []Stmt,
	allocator := context.allocator,
) -> Error {
	env := new(Env, allocator)
	env.enclosing = outer_env
	env.values = make(map[string]Value, allocator)

	for stmt in stmts {
		stmt_execute(stmt, env, allocator) or_return
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
	if parser_match(p, {.Fun}) {
		fn, err := parser_stmt_function(p, allocator)
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
	allocator := context.allocator,
	is_method := false,
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
	fn.call = function_call
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

stmt_execute :: proc(stmt: Stmt, env: ^Env, allocator := context.allocator) -> Error {
	switch v in stmt {
	case (^Stmt_Expr):
		expr_to_value(v.expr, env) or_return
	case (^Stmt_Print):
		val := expr_to_value(v.expr, env) or_return
		str := value_to_string(val)
		fmt.println(str)
	case (^Stmt_Var):
		val: Value
		if v.initializer != nil {
			val = expr_to_value(v.initializer, env) or_return
		}
		env_define(env, v.name.lexeme, val)
	case (^Stmt_Block):
		env_execute_block(env, v.statements, allocator) or_return
	case (^Stmt_If):
		val := expr_to_value(v.condition, env) or_return
		if value_is_truthy(val) {
			stmt_execute(v.branch_then, env) or_return
		} else if v.branch_else != nil {
			stmt_execute(v.branch_else, env) or_return
		}
	case (^Stmt_While):
		for {
			val := expr_to_value(v.condition, env) or_return
			if !value_is_truthy(val) {
				break
			}
			stmt_execute(v.body, env) or_return
		}
	case (^Stmt_Function):
		fn := Function {
			decl    = v,
			closure = env,
		}
		env_define(env, v.name.lexeme, fn)
	case (^Stmt_Return):
		val: Value
		if v.value != nil {
			val = expr_to_value(v.value, env, allocator) or_return
		}

		return Error_Return_Propagation{val}
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
	case nil, f64, bool, Object, [dynamic]Value:
		return fmt.aprintf("%#v", v, allocator = allocator)
	case Function:
		if v.decl.call == function_call {
			return fmt.aprintf("<fn %s>", v.decl.name.lexeme)
		} else {
			return fmt.aprintf("<native fn %s>", v.decl.name.lexeme)
		}
	}
	return ""
}

function_call :: proc(
	fn: ^Function,
	args: []Value,
	allocator := context.allocator,
) -> (
	Value,
	Error,
) {
	fn_env := new(Env, allocator)
	defer free(fn_env)
	fn_env.enclosing = fn.closure

	for i in 0 ..< len(args) {
		env_define(fn_env, fn.decl.params[i].lexeme, args[i])
	}
	possible_err := env_execute_block(fn_env, fn.decl.body, allocator)
	result, is_result := possible_err.(Error_Return_Propagation)
	if is_result {
		return result.val, nil
	}
	return nil, possible_err
}
