package provider

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"
)

// hashForState computes the hexadecimal representation of the SHA1 checksum of a string.
// This is used by most resources/data-sources here to compute their Unique Identifier (ID).
func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}

// overridableTimeFunc normally returns time.Now(),
// but it is overridden during testing to simulate an arbitrary value of "now".
var overridableTimeFunc = func() time.Time {
	return time.Now()
}
