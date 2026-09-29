package httpkit

import "errors"

var (
	// ErrMalformed is wrapped by every error returned for input that is not
	// valid HTTP. Use errors.Is to test for it.
	ErrMalformed = errors.New("httpkit: malformed message")

	// ErrTooLarge is wrapped by errors returned when input exceeds a limit
	// from ReadOptions.
	ErrTooLarge = errors.New("httpkit: message too large")
)

// malformedError describes what was wrong with the input. It wraps
// ErrMalformed.
type malformedError struct {
	what string
}

func (e *malformedError) Error() string { return "httpkit: malformed " + e.what }
func (e *malformedError) Unwrap() error { return ErrMalformed }

func malformed(what string) error { return &malformedError{what: what} }

type tooLargeError struct {
	what string
}

func (e *tooLargeError) Error() string { return "httpkit: " + e.what + " too large" }
func (e *tooLargeError) Unwrap() error { return ErrTooLarge }

func tooLarge(what string) error { return &tooLargeError{what: what} }
