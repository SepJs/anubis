// Package encoding provides payload obfuscation techniques for WAF bypass
// including double URL encoding, nested Base64, Unicode escape, UTF-16,
// mixed case, null-byte injection, and comment injection.
package encoding

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

type Encoder struct {
	encodingChain []EncodingFunc
}

type EncodingFunc func(string) (string, error)

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (e *Encoder) AddEncoding(enc EncodingFunc) *Encoder {
	e.encodingChain = append(e.encodingChain, enc)
	return e
}

func (e *Encoder) Encode(input string) (string, error) {
	result := input
	for _, enc := range e.encodingChain {
		var err error
		result, err = enc(result)
		if err != nil {
			return "", err
		}
	}
	return result, nil
}

func URLEncode(input string) (string, error) {
	return url.QueryEscape(input), nil
}

func DoubleURLEncode(input string) (string, error) {
	first := url.QueryEscape(input)
	return url.QueryEscape(first), nil
}

func Base64Encode(input string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(input)), nil
}

func Base64URLEncode(input string) (string, error) {
	return base64.URLEncoding.EncodeToString([]byte(input)), nil
}

func NestedBase64Encode(input string, depth int) (string, error) {
	result := input
	for i := 0; i < depth; i++ {
		result = base64.StdEncoding.EncodeToString([]byte(result))
	}
	return result, nil
}

func HexEncode(input string) (string, error) {
	return fmt.Sprintf("%x", []byte(input)), nil
}

func UnicodeEscape(input string) (string, error) {
	var sb strings.Builder
	for _, r := range input {
		sb.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return sb.String(), nil
}

func UTF16Encode(input string) (string, error) {
	var sb strings.Builder
	for _, r := range input {
		sb.WriteString(fmt.Sprintf("%%%04X%%00", r))
	}
	return sb.String(), nil
}

func MixedCase(input string) (string, error) {
	var sb strings.Builder
	for _, r := range input {
		if r >= 'a' && r <= 'z' {
			sb.WriteRune(r - 32)
		} else if r >= 'A' && r <= 'Z' {
			sb.WriteRune(r + 32)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String(), nil
}

func NullByteInsert(input string) (string, error) {
	return input + "%00", nil
}

func CommentInject(input string) (string, error) {
	result := strings.ReplaceAll(input, " ", "/**/")
	return result, nil
}

func BuildWAFBypassEncoder() *Encoder {
	return NewEncoder().
		AddEncoding(URLEncode).
		AddEncoding(CommentInject).
		AddEncoding(DoubleURLEncode)
}

func BuildSQLIEncoder() *Encoder {
	return NewEncoder().
		AddEncoding(URLEncode).
		AddEncoding(CommentInject).
		AddEncoding(NullByteInsert)
}

func BuildXSSEncoder() *Encoder {
	return NewEncoder().
		AddEncoding(UnicodeEscape).
		AddEncoding(URLEncode)
}
