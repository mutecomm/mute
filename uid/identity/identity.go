// Package identity contains helper functions for Mute identities.
package identity

import (
	"errors"
	"fmt"
	"strings"
)

// Alphabet defines the alphabet for the localpart of Mute identities.
const Alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-."

// ErrNotMapped is returned if an identity is not well-formed or not mapped.
var ErrNotMapped = errors.New("identity: identity is not well-formed or not mapped")

// Map maps the given identity to the allowed character set and reports
// unrecoverable errors.
func Map(identity string) (string, error) {
	lp, domain, err := Split(identity)
	if err != nil {
		return "", err
	}
	mlp, err := MapLocalpart(lp)
	if err != nil {
		return "", err
	}
	return mlp + "@" + MapDomain(domain), nil
}

// IsMapped returns an error, if the given identity is not well-formed or not
// mapped.
func IsMapped(identity string) error {
	mappedID, err := Map(identity)
	if err != nil || mappedID != identity {
		return ErrNotMapped
	}
	return nil
}

// MapPlus maps the given identity to the allowed character set and reports
// unrecoverable errors (like Map). Additionally, it also returns the mapped domain
// for further use.
func MapPlus(identity string) (mappedID, mappedDomain string, err error) {
	lp, domain, err := Split(identity)
	if err != nil {
		return "", "", err
	}
	mlp, err := MapLocalpart(lp)
	if err != nil {
		return "", "", err
	}
	mappedDomain = MapDomain(domain)
	mappedID = mlp + "@" + mappedDomain
	return
}

// MapLocalpart maps the given localpart to the allowed character set and
// reports unrecoverable errors.
func MapLocalpart(localpart string) (string, error) {
	// trim leading and trailing spaces
	lp := strings.TrimSpace(localpart)

	// convert to lowercase
	lp = strings.ToLower(lp)

	// enforce minimum length
	if len(lp) < 3 {
		return "", errors.New("identity: minimum length is 3")
	}

	// no '-' or '.' in the beginning
	if lp[0] == '-' {
		return "", errors.New("identity: starting with '-' not allowed")
	}
	if lp[0] == '.' {
		return "", errors.New("identity: starting with '.' not allowed")
	}

	// no '-' or '.' in the end
	if lp[len(lp)-1] == '-' {
		return "", errors.New("identity: ending with '-' not allowed")
	}
	if lp[len(lp)-1] == '.' {
		return "", errors.New("identity: ending with '.' not allowed")
	}

	// no "--"
	if strings.Contains(lp, "--") {
		return "", errors.New("identity: sequence '--' not allowed")
	}

	// no "-."
	if strings.Contains(lp, "-.") {
		return "", errors.New("identity: sequence '-.' not allowed")
	}

	// no ".-"
	if strings.Contains(lp, ".-") {
		return "", errors.New("identity: sequence '.-' not allowed")
	}

	// no ".."
	if strings.Contains(lp, "..") {
		return "", errors.New("identity: sequence '..' not allowed")
	}

	// enforce mapping and report illegal characters
	var err error
	mapping := func(r rune) rune {
		switch {
		case r == '0':
			return 'o'
		case r == '1':
			return 'l'
		case r == 'j':
			return 'i'
		case r >= 'a' && r <= 'z':
			return r
		case r >= '2' && r <= '9':
			return r
		case r == '-' || r == '.':
			return r
		default:
			err = fmt.Errorf("identity: character '%v' not allowed", r)
		}
		return r
	}
	lp = strings.Map(mapping, lp)
	if err != nil {
		return "", err
	}

	// enforce maximum length
	if len(lp) > 64 {
		return "", errors.New("identity: maximum length is 64")
	}

	return lp, nil
}

// MapDomain maps the given domain to lower case.
func MapDomain(domain string) string {
	return strings.ToLower(domain)
}

// Split splits the given identity into localpart and domain.
func Split(identity string) (localpart, domain string, err error) {
	parts := strings.Split(identity, "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("identity: '%s' does not contain exactly one '@'", identity)
	}
	return parts[0], parts[1], nil
}
