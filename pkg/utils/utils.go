package utils

import (
	"log/slog"
	"regexp"
)

type DebugWriter struct {
}

func (d *DebugWriter) Write(p []byte) (n int, err error) {
	slog.Debug("boundary", "output", string(p))

	return len(p), nil
}

func PadLeft(str string, length int) string {
	for len(str) < length {
		str = "0" + str
	}
	return str
}

func FormatPort(name string, length int) string {
	re2 := regexp.MustCompile(`[^0-9]+`)

	// Get all digits from the string
	port := re2.ReplaceAllString(name, "")

	return PadLeft(port, length)
}
