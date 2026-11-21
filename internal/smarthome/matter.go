package smarthome

import (
	"errors"
	"strconv"
	"strings"
)

// PairingCode is a checked Matter setup or pairing code.
type PairingCode struct {
	Code      string `json:"-"`         // normalised: digits only, or the MT: QR payload
	Kind      string `json:"kind"`      // manual | qr
	Formatted string `json:"formatted"` // 1234-567-8901 style, partly masked
	// Discriminator is the short (4-bit) discriminator from a manual code; it helps tell
	// devices apart when several are waiting to be paired.
	Discriminator int  `json:"discriminator"`
	VendorPresent bool `json:"vendor_present,omitempty"` // a 21-digit code carries vendor and product ids
}

var errCode = errors.New("that doesn't look like a Matter code: use the 11-digit pairing code (e.g. 3497-011-2332) or the text of the QR code (MT:...)")

// Passcodes the Matter specification forbids.
var badPasscodes = map[int]bool{0: true, 11111111: true, 22222222: true, 33333333: true, 44444444: true, 55555555: true,
	66666666: true, 77777777: true, 88888888: true, 99999999: true, 12345678: true, 87654321: true}

// ParsePairingCode checks a Matter manual pairing code (11 or 21 digits, as Google Home,
// Alexa and Apple Home show when you share a device) or a QR code payload ("MT:...").
func ParsePairingCode(s string) (*PairingCode, error) {
	s = strings.TrimSpace(s)
	if up := strings.ToUpper(s); strings.HasPrefix(up, "MT:") {
		body := up[3:]
		if len(body) < 19 || len(body) > 400 {
			return nil, errCode
		}
		for _, r := range body {
			if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r == '-' || r == '.') {
				return nil, errCode
			}
		}
		return &PairingCode{Code: up, Kind: "qr", Formatted: "MT:" + body[:4] + "…"}, nil
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '.':
		default:
			return nil, errCode
		}
	}
	d := b.String()
	if len(d) != 11 && len(d) != 21 {
		return nil, errCode
	}
	if !verhoeffValid(d) {
		return nil, errors.New("that pairing code has a typo (its check digit doesn't match); copy it again from the app")
	}
	first := int(d[0] - '0')
	long := first&4 != 0
	if first > 7 || long != (len(d) == 21) {
		return nil, errCode
	}
	chunk2, _ := strconv.Atoi(d[1:6])
	chunk3, _ := strconv.Atoi(d[6:10])
	if chunk2 > 0xFFFF {
		return nil, errCode
	}
	passcode := chunk3<<14 | chunk2&0x3FFF
	if passcode < 1 || passcode > 99999998 || badPasscodes[passcode] {
		return nil, errors.New("that pairing code holds a passcode Matter doesn't allow; copy it again from the app")
	}
	return &PairingCode{
		Code:          d,
		Kind:          "manual",
		Formatted:     d[:4] + "-" + d[4:7] + "-••••",
		Discriminator: (first&3)<<2 | chunk2>>14,
		VendorPresent: long,
	}, nil
}

// Verhoeff check digit tables.
var (
	vD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	vP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	vInv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
)

func verhoeffValid(digits string) bool {
	c := 0
	for i := 0; i < len(digits); i++ {
		c = vD[c][vP[i%8][int(digits[len(digits)-1-i]-'0')]]
	}
	return c == 0
}

// VerhoeffDigit returns the check digit to append to digits.
func VerhoeffDigit(digits string) byte {
	c := 0
	for i := 0; i < len(digits); i++ {
		c = vD[c][vP[(i+1)%8][int(digits[len(digits)-1-i]-'0')]]
	}
	return byte('0' + vInv[c])
}
