package lox

import "base:runtime"

token_to_string :: #force_inline proc(token: Token) -> string {
	return transmute(string)runtime.Raw_String{data = token.start, len = token.length}
}

