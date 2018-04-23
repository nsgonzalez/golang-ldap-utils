package main

import (
	"strings"
)

func flipSlice(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func trimTrailingComma(s string) string {
	if strings.HasSuffix(s, ",") {
		s = s[:len(s)-len(",")]
	}
	return s
}
