package password

import "strings"

var commonPasswords = map[string]struct{}{
	"123456":    {},
	"password":  {},
	"123456789": {},
	"12345678":  {},
	"qwerty":    {},
	"abc123":    {},
	"password1": {},
	"111111":    {},
	"123123":    {},
	"letmein":   {},
	"welcome":   {},
	"admin":     {},
	"dragon":    {},
	"football":  {},
	"iloveyou":  {},
	"monkey":    {},
	"sunshine":  {},
	"princess":  {},
	"qwerty123": {},
	"login":     {},
}

// IsCommonPassword returns true when the password is part of a curated list of common passwords.
func IsCommonPassword(password string) bool {
	_, ok := commonPasswords[strings.ToLower(password)]
	return ok
}
