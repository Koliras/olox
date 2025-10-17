package lox

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:unicode/utf8"

Scanner :: struct {
	start:   ^byte,
	current: [^]byte,
	line:    int,
	end:     ^byte,
}

scanner_init :: proc(scanner: ^Scanner, source: []byte) {
	scanner.start = &source[0]
	scanner.current = &source[0]
	scanner.line = 1
	if len(source) > 0 {
		#no_bounds_check scanner.end = &source[len(source) - 1]
	}
}

scanner_scan_token :: proc(s: ^Scanner) -> Token {
	scanner_skip_whitespace(s)
	s.start = s.current
	if scanner_is_at_end(s) {
		return scanner_make_token(s, .Eof)
	}

	c := scanner_advance(s)
	if char_is_alpha(c) {
		return scanner_identifier(s)
	}
	if char_is_digit(c) {
		return scanner_number(s)
	}
	switch c {
	case '{':
		return scanner_make_token(s, .Left_Brace)
	case '}':
		return scanner_make_token(s, .Right_Brace)
	case '(':
		return scanner_make_token(s, .Left_Paren)
	case ')':
		return scanner_make_token(s, .Right_Paren)
	case ';':
		return scanner_make_token(s, .Semicolon)
	case ',':
		return scanner_make_token(s, .Comma)
	case '.':
		return scanner_make_token(s, .Dot)
	case '-':
		return scanner_make_token(s, .Minus)
	case '+':
		return scanner_make_token(s, .Plus)
	case '/':
		return scanner_make_token(s, .Slash)
	case '*':
		return scanner_make_token(s, .Star)
	case '!':
		return scanner_make_token(s, scanner_match(s, '=') ? .Bang_Equal : .Bang)
	case '=':
		return scanner_make_token(s, scanner_match(s, '=') ? .Equal_Equal : .Equal)
	case '<':
		return scanner_make_token(s, scanner_match(s, '=') ? .Less_Equal : .Less)
	case '>':
		return scanner_make_token(s, scanner_match(s, '=') ? .Greater_Equal : .Greater)
	case '"':
		return scanner_string(s)
	}
	return scanner_error_token(s, "Unexpected character.")
}

scanner_is_at_end :: proc(s: ^Scanner) -> bool {
	return s.current[0] == 0
}

scanner_peek :: proc(s: ^Scanner) -> byte {
	return s.current[0]
}

scanner_peek_next :: proc(s: ^Scanner) -> byte {
	if scanner_is_at_end(s) do return 0
	return s.current[1]
}

scanner_advance :: proc(s: ^Scanner) -> byte {
	current := s.current[0]
	s.current = &s.current[1]
	return current
}

scanner_skip_whitespace :: proc(s: ^Scanner) {
	for {
		char := scanner_peek(s)
		switch char {
		case ' ', '\r', '\t':
			scanner_advance(s)
		case '\n':
			s.line += 1
			scanner_advance(s)
		case '/':
			if next := scanner_peek_next(s); next == '/' {
				for scanner_peek(s) != '\n' {
					scanner_advance(s)
				}
			} else {
				return
			}
		case:
			return
		}
	}
}

scanner_match :: proc(s: ^Scanner, expected: byte) -> bool {
	if scanner_is_at_end(s) do return false
	current := s.current[0]
	if current != expected do return false
	s.current = &s.current[1]
	return true
}

Token :: struct {
	type:   Token_Type,
	start:  [^]byte,
	length: int,
	line:   int,
}

Token_Type :: enum {
	// Single-character tokens.
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

	// One or two character tokens.
	Bang,
	Bang_Equal,
	Equal,
	Equal_Equal,
	Greater,
	Greater_Equal,
	Less,
	Less_Equal,

	// Literals.
	Identifier,
	String,
	Number,

	// Keywords.
	And,
	Class,
	Else,
	False,
	For,
	Fun,
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

	// Special.
	Error,
	Eof,
}

scanner_make_token :: proc(s: ^Scanner, type: Token_Type) -> Token {
	return {
		type = type,
		start = s.start,
		length = int(uintptr(s.current) - uintptr(s.start)),
		line = s.line,
	}
}

scanner_error_token_from_bytes :: proc(s: ^Scanner, msg: []byte) -> Token {
	return {type = .Error, start = raw_data(msg), length = len(msg), line = s.line}
}
scanner_error_token_from_string :: #force_inline proc(s: ^Scanner, msg: string) -> Token {
	return scanner_error_token_from_bytes(s, transmute([]byte)(string("Unterminated string.")))
}

scanner_error_token :: proc {
	scanner_error_token_from_bytes,
	scanner_error_token_from_string,
}

scanner_string :: proc(s: ^Scanner) -> Token {
	for scanner_peek(s) != '"' && !scanner_is_at_end(s) {
		if scanner_peek(s) == '\n' do s.line += 1
		scanner_advance(s)
	}

	if scanner_is_at_end(s) {
		return scanner_error_token(s, "Unterminated string.")
	}

	scanner_advance(s)
	return scanner_make_token(s, .String)
}

scanner_number :: proc(s: ^Scanner) -> Token {
	for char_is_digit(scanner_peek(s)) {
		scanner_advance(s)
	}
	if scanner_peek(s) == '.' && char_is_digit(scanner_peek_next(s)) {
		scanner_advance(s) // consume '.'
		for char_is_digit(scanner_peek(s)) {
			scanner_advance(s)
		}
	}

	return scanner_make_token(s, .Number)
}

scanner_identifier :: proc(s: ^Scanner) -> Token {
	for char_is_alpha(scanner_peek(s)) || char_is_digit(scanner_peek(s)) {
		scanner_advance(s)
	}
	return scanner_make_token(s, scanner_identifier_type(s))
}

scanner_identifier_type :: proc(s: ^Scanner) -> Token_Type {
	switch s.start^ {
	case 'a':
		return scanner_check_keyword(s, 1, 2, "nd", .And)
	case 'c':
		return scanner_check_keyword(s, 1, 4, "lass", .Class)
	case 'e':
		return scanner_check_keyword(s, 1, 3, "lse", .Else)
	case 'f':
		if int(uintptr(s.current) - uintptr(s.start)) > 1 {
			next := (cast([^]byte)s.start)[1]
			switch next {
			case 'a':
				return scanner_check_keyword(s, 2, 3, "lse", .False)
			case 'o':
				return scanner_check_keyword(s, 2, 1, "r", .For)
			case 'u':
				return scanner_check_keyword(s, 2, 1, "n", .Fun)
			}
		}
	case 'i':
		return scanner_check_keyword(s, 1, 1, "f", .If)
	case 'n':
		return scanner_check_keyword(s, 1, 2, "il", .Nil)
	case 'o':
		return scanner_check_keyword(s, 1, 1, "r", .Or)
	case 'p':
		return scanner_check_keyword(s, 1, 4, "rint", .Print)
	case 'r':
		return scanner_check_keyword(s, 1, 5, "eturn", .Return)
	case 's':
		return scanner_check_keyword(s, 1, 4, "uper", .Super)
	case 't':
		if int(uintptr(s.current) - uintptr(s.start)) > 1 {
			next := (cast([^]byte)s.start)[1]
			switch next {
			case 'h':
				return scanner_check_keyword(s, 2, 2, "is", .This)
			case 'r':
				return scanner_check_keyword(s, 2, 2, "ue", .True)
			}
		}

	case 'v':
		return scanner_check_keyword(s, 1, 2, "ar", .Var)
	case 'w':
		return scanner_check_keyword(s, 1, 4, "hile", .While)
	}
	return .Identifier
}

scanner_check_keyword :: proc(
	s: ^Scanner,
	start, length: int,
	rest: string,
	type: Token_Type,
) -> Token_Type {
	if int(uintptr(s.current) - uintptr(s.start)) == start + length &&
	   mem.compare((cast([^]byte)s.start)[start:start + length], transmute([]byte)rest) == 0 {
		return type
	}
	return .Identifier
}

char_is_digit :: proc(r: byte) -> bool {
	return r >= '0' && r <= '9'
}

char_is_alpha :: proc(b: byte) -> bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}
