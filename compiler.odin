package lox

import "base:runtime"
import clang "core:c"
import "core:fmt"
import os_old "core:os"
import "core:strconv"

compile :: proc(source: []byte, chunk: ^Chunk) -> bool {
	scanner: Scanner
	scanner_init(&scanner, source)
	parser: Parser
	parser.scanner = &scanner
	parser.chunk = chunk
	parser_advance(&parser)
	parser_expression(&parser)
	parser_consume(&parser, .Eof, "Expect end of expression.")
	parser_end_compiler(&parser)
	return !parser.had_error
}

Parser :: struct {
	previous:   Token,
	current:    Token,
	scanner:    ^Scanner,
	had_error:  bool,
	panic_mode: bool,
	chunk:      ^Chunk,
}

Parse_Precedence :: enum u8 {
	None,
	Assignment,
	Or,
	And,
	Equality,
	Comparison,
	Term,
	Factor,
	Unary,
	Call,
	Primary,
}

Parse_Fn :: proc(parser: ^Parser)
Parse_Rule :: struct {
	prefix, infix: Parse_Fn,
	precedence:    Parse_Precedence,
}

PARSER_RULES: [Token_Type]Parse_Rule = {
	.Left_Paren    = {parser_grouping, nil, .None},
	.Right_Paren   = {nil, nil, .None},
	.Left_Brace    = {nil, nil, .None},
	.Right_Brace   = {nil, nil, .None},
	.Comma         = {nil, nil, .None},
	.Dot           = {nil, nil, .None},
	.Minus         = {parser_unary, parser_binary, .Term},
	.Plus          = {nil, parser_binary, .Term},
	.Semicolon     = {nil, nil, .None},
	.Slash         = {nil, parser_binary, .Factor},
	.Star          = {nil, parser_binary, .Factor},
	.Bang          = {parser_unary, nil, .None},
	.Bang_Equal    = {nil, parser_binary, .Equality},
	.Equal         = {nil, nil, .None},
	.Equal_Equal   = {nil, parser_binary, .Equality},
	.Greater       = {nil, parser_binary, .Comparison},
	.Greater_Equal = {nil, parser_binary, .Comparison},
	.Less          = {nil, parser_binary, .Comparison},
	.Less_Equal    = {nil, parser_binary, .Comparison},
	.Identifier    = {nil, nil, .None},
	.String        = {nil, nil, .None},
	.Number        = {parser_number, nil, .None},
	.And           = {nil, nil, .None},
	.Class         = {nil, nil, .None},
	.Else          = {nil, nil, .None},
	.False         = {parser_literal, nil, .None},
	.For           = {nil, nil, .None},
	.Fun           = {nil, nil, .None},
	.If            = {nil, nil, .None},
	.Nil           = {parser_literal, nil, .None},
	.Or            = {nil, nil, .None},
	.Print         = {nil, nil, .None},
	.Return        = {nil, nil, .None},
	.Super         = {nil, nil, .None},
	.This          = {nil, nil, .None},
	.True          = {parser_literal, nil, .None},
	.Var           = {nil, nil, .None},
	.While         = {nil, nil, .None},
	.Error         = {nil, nil, .None},
	.Eof           = {nil, nil, .None},
}

parser_advance :: proc(p: ^Parser) {
	p.previous = p.current

	for {
		p.current = scanner_scan_token(p.scanner)
		if p.current.type != .Error do break
		parser_error_at_current(p, token_to_string(p.current))
	}
}

parser_error_at_current :: proc(p: ^Parser, message: string) {
	parser_error_at(p, &p.current, message)
}
parser_error :: proc(p: ^Parser, message: string) {
	parser_error_at(p, &p.previous, message)
}
parser_error_at :: proc(p: ^Parser, token: ^Token, message: string) {
	if p.panic_mode do return
	p.panic_mode = true
	fmt.fprintf(os_old.stderr, "[line %d] Error", token.line)

	if token.type == .Eof {
		fmt.fprintf(os_old.stderr, " at end")
	} else if token.type == .Error {
	} else {
		fmt.fprintf(os_old.stderr, " at '%.*s'", token.length, token.start)
	}

	fmt.fprintf(os_old.stderr, ": %s\n", message)
	p.had_error = true
}

parser_expression :: proc(p: ^Parser) {
	parser_parse_precedence(p, .Assignment)
}

parser_consume :: proc(p: ^Parser, type: Token_Type, message: string) {
	if p.current.type == type {
		parser_advance(p)
		return
	}

	parser_error_at_current(p, message)
}

parser_emit_byte :: proc(p: ^Parser, b: byte) {
	chunk_write(p.chunk, b, p.previous.line)
}

parser_emit_bytes :: proc(p: ^Parser, b1, b2: byte) {
	chunk_write(p.chunk, b1, p.previous.line)
	chunk_write(p.chunk, b2, p.previous.line)
}

parser_emit_return :: proc(p: ^Parser) {
	parser_emit_byte(p, cast(byte)Op_Code.Return)
}

parser_emit_constant :: proc(p: ^Parser, val: Value) {
	parser_emit_bytes(p, cast(byte)Op_Code.Constant, parser_make_constant(p, val, p.chunk))
}

parser_make_constant :: proc(p: ^Parser, val: Value, chunk: ^Chunk = nil) -> byte {
	chunk := chunk
	if chunk == nil {
		chunk = p.chunk
	}
	const := chunk_add_const(chunk, val)
	if const > int(clang.UINT8_MAX) {
		parser_error(p, "Too many constants in one chunk.")
		return 0
	}
	return byte(const)
}

parser_end_compiler :: proc(p: ^Parser) {
	parser_emit_return(p)
	when ODIN_DEBUG {
		if !p.had_error {
			disassemble_chunk(p.chunk, "code")
		}
	}
}

parser_grouping :: proc(p: ^Parser) {
	parser_expression(p)
	parser_consume(p, .Right_Paren, "Expect ')' after expression.")
}

parser_unary :: proc(p: ^Parser) {
	operator_type := p.previous.type
	parser_parse_precedence(p, .Unary)

	#partial switch operator_type {
	case .Bang:
		parser_emit_byte(p, byte(Op_Code.Not))
	case .Minus:
		parser_emit_byte(p, byte(Op_Code.Negate))
	case:
		unreachable()
	}
}

parser_binary :: proc(p: ^Parser) {
	operator_type := p.previous.type
	rule := get_rule(operator_type)
	parser_parse_precedence(p, Parse_Precedence(byte(rule.precedence) + 1))

	#partial switch operator_type {
	case .Bang_Equal:
		parser_emit_bytes(p, byte(Op_Code.Equal), byte(Op_Code.Not))
	case .Equal_Equal:
		parser_emit_byte(p, byte(Op_Code.Equal))
	case .Greater_Equal:
		parser_emit_bytes(p, byte(Op_Code.Less), byte(Op_Code.Not))
	case .Greater:
		parser_emit_byte(p, byte(Op_Code.Greater))
	case .Less_Equal:
		parser_emit_bytes(p, byte(Op_Code.Greater), byte(Op_Code.Not))
	case .Less:
		parser_emit_byte(p, byte(Op_Code.Less))
	case .Plus:
		parser_emit_byte(p, byte(Op_Code.Add))
	case .Minus:
		parser_emit_byte(p, byte(Op_Code.Substract))
	case .Star:
		parser_emit_byte(p, byte(Op_Code.Multiply))
	case .Slash:
		parser_emit_byte(p, byte(Op_Code.Devide))
	case:
		unreachable()
	}
}

parser_parse_precedence :: proc(p: ^Parser, precedence: Parse_Precedence) {
	parser_advance(p)
	prefix_rule := get_rule(p.previous.type).prefix
	if prefix_rule == nil {
		parser_error(p, "Expect expression.")
		return
	}
	prefix_rule(p)

	for byte(precedence) <= byte(get_rule(p.current.type).precedence) {
		parser_advance(p)
		infix_rule := get_rule(p.previous.type).infix
		infix_rule(p)
	}
}

parser_number :: proc(p: ^Parser) {
	val, _ := strconv.parse_f64(token_to_string(p.previous))
	parser_emit_constant(p, value_number(val))
}

parser_literal :: proc(p: ^Parser) {
	#partial switch p.previous.type {
	case .False:
		parser_emit_byte(p, byte(Op_Code.False))
	case .True:
		parser_emit_byte(p, byte(Op_Code.True))
	case .Nil:
		parser_emit_byte(p, byte(Op_Code.Nil))
	case:
		unreachable()
	}
}

get_rule :: proc(type: Token_Type) -> ^Parse_Rule {
	return &PARSER_RULES[type]
}
