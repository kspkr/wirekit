package httpkit

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kspkr/wirekit/internal/ascii"
)

// Cookie is one name/value pair from a Cookie request header.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// String returns the pair as it appears in a Cookie header: "name=value".
func (c Cookie) String() string {
	return c.Name + "=" + c.Value
}

// ToStd converts the cookie to its net/http equivalent.
func (c Cookie) ToStd() *http.Cookie {
	return &http.Cookie{Name: c.Name, Value: c.Value}
}

// ParseCookies parses the value of a Cookie request header into its pairs,
// in order.
//
// Parsing is lenient, as browsers are: pairs are split on ';', surrounding
// whitespace is trimmed, empty pairs are dropped, and a pair without '='
// becomes a cookie with an empty Name. Values are returned exactly as sent,
// including any surrounding double quotes.
func ParseCookies(header string) []Cookie {
	var out []Cookie
	for part := range strings.SplitSeq(header, ";") {
		part = ascii.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, found := strings.Cut(part, "=")
		if !found {
			out = append(out, Cookie{Value: part})
			continue
		}
		out = append(out, Cookie{Name: ascii.TrimSpace(name), Value: ascii.TrimSpace(value)})
	}
	return out
}

// SameSite is the value of a cookie's SameSite attribute.
type SameSite int

// SameSite values. SameSiteDefault means the attribute was absent or
// unrecognized; the others correspond to SameSite=Lax, Strict and None.
const (
	SameSiteDefault SameSite = iota
	SameSiteLax
	SameSiteStrict
	SameSiteNone
)

// String returns the attribute value ("Lax", "Strict", "None"), or "" for
// SameSiteDefault.
func (s SameSite) String() string {
	switch s {
	case SameSiteLax:
		return "Lax"
	case SameSiteStrict:
		return "Strict"
	case SameSiteNone:
		return "None"
	}
	return ""
}

// MarshalText implements encoding.TextMarshaler so SameSite serializes as
// its attribute value.
func (s SameSite) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *SameSite) UnmarshalText(b []byte) error {
	switch {
	case len(b) == 0:
		*s = SameSiteDefault
	case ascii.EqualFold(string(b), "lax"):
		*s = SameSiteLax
	case ascii.EqualFold(string(b), "strict"):
		*s = SameSiteStrict
	case ascii.EqualFold(string(b), "none"):
		*s = SameSiteNone
	default:
		return fmt.Errorf("httpkit: unknown SameSite value %q", b)
	}
	return nil
}

// SetCookie is a parsed Set-Cookie response header.
//
// Fields hold the attributes as written, with light normalization: attribute
// names are matched case-insensitively and Expires is parsed into a time.
// Attributes that are not understood are kept in Unparsed so nothing is
// lost.
type SetCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`

	Path   string `json:"path,omitempty"`
	Domain string `json:"domain,omitempty"`

	// Expires is the parsed Expires attribute, or the zero time when the
	// attribute was absent or could not be parsed. RawExpires keeps the
	// attribute text in both cases.
	Expires    time.Time `json:"expires,omitzero"`
	RawExpires string    `json:"rawExpires,omitempty"`

	// MaxAge follows net/http's convention: 0 means the attribute was
	// absent, a negative value means "Max-Age=0" (delete now), and a
	// positive value is the lifetime in seconds.
	MaxAge int `json:"maxAge,omitempty"`

	Secure      bool     `json:"secure,omitempty"`
	HttpOnly    bool     `json:"httpOnly,omitempty"`
	SameSite    SameSite `json:"sameSite,omitempty"`
	Partitioned bool     `json:"partitioned,omitempty"`

	// Unparsed holds attributes that were not recognized, as written.
	Unparsed []string `json:"unparsed,omitempty"`

	// Raw is the header value the cookie was parsed from, or "" for a
	// cookie built by hand.
	Raw string `json:"-"`
}

// ParseSetCookie parses one Set-Cookie header value.
//
// Following RFC 6265 §5.2, the only fatal error is a first segment without
// an '=' character. Everything else is accepted: unknown attributes go to
// Unparsed, an unparseable Expires leaves Expires zero with RawExpires set,
// and an invalid Max-Age is kept in Unparsed. Use [SetCookie.Validate] to
// find out whether a browser would accept the result.
func ParseSetCookie(line string) (SetCookie, error) {
	line = ascii.TrimSpace(line)
	c := SetCookie{Raw: line}
	pair, rest, _ := strings.Cut(line, ";")
	name, value, found := strings.Cut(pair, "=")
	if !found {
		return SetCookie{}, malformed("Set-Cookie: missing '=' in name-value pair")
	}
	c.Name = ascii.TrimSpace(name)
	c.Value = ascii.TrimSpace(value)

	for attr := range strings.SplitSeq(rest, ";") {
		attr = ascii.TrimSpace(attr)
		if attr == "" {
			continue
		}
		key, val, hasVal := strings.Cut(attr, "=")
		key = ascii.TrimSpace(key)
		val = ascii.TrimSpace(val)
		switch ascii.ToLower(key) {
		case "path":
			c.Path = val
		case "domain":
			c.Domain = val
		case "expires":
			c.RawExpires = val
			if t, ok := ParseCookieDate(val); ok {
				c.Expires = t
			}
		case "max-age":
			secs, err := strconv.Atoi(val)
			if err != nil || !hasVal || (secs != 0 && val[0] == '0') {
				c.Unparsed = append(c.Unparsed, attr)
				continue
			}
			if secs <= 0 {
				secs = -1
			}
			c.MaxAge = secs
		case "secure":
			c.Secure = true
		case "httponly":
			c.HttpOnly = true
		case "partitioned":
			c.Partitioned = true
		case "samesite":
			switch {
			case ascii.EqualFold(val, "lax"):
				c.SameSite = SameSiteLax
			case ascii.EqualFold(val, "strict"):
				c.SameSite = SameSiteStrict
			case ascii.EqualFold(val, "none"):
				c.SameSite = SameSiteNone
			default:
				c.Unparsed = append(c.Unparsed, attr)
			}
		default:
			c.Unparsed = append(c.Unparsed, attr)
		}
	}
	return c, nil
}

// String serializes the cookie as a Set-Cookie header value. Expires is
// written in the RFC 1123 form browsers expect; when Expires is zero but
// RawExpires is set, RawExpires is written unchanged.
func (c SetCookie) String() string {
	var sb strings.Builder
	sb.Grow(len(c.Name) + len(c.Value) + 64)
	sb.WriteString(c.Name)
	sb.WriteByte('=')
	sb.WriteString(c.Value)
	if c.Path != "" {
		sb.WriteString("; Path=")
		sb.WriteString(c.Path)
	}
	if c.Domain != "" {
		sb.WriteString("; Domain=")
		sb.WriteString(c.Domain)
	}
	switch {
	case !c.Expires.IsZero():
		sb.WriteString("; Expires=")
		sb.WriteString(c.Expires.UTC().Format(http.TimeFormat))
	case c.RawExpires != "":
		sb.WriteString("; Expires=")
		sb.WriteString(c.RawExpires)
	}
	if c.MaxAge > 0 {
		sb.WriteString("; Max-Age=")
		sb.WriteString(strconv.Itoa(c.MaxAge))
	} else if c.MaxAge < 0 {
		sb.WriteString("; Max-Age=0")
	}
	if c.Secure {
		sb.WriteString("; Secure")
	}
	if c.HttpOnly {
		sb.WriteString("; HttpOnly")
	}
	if c.SameSite != SameSiteDefault {
		sb.WriteString("; SameSite=")
		sb.WriteString(c.SameSite.String())
	}
	if c.Partitioned {
		sb.WriteString("; Partitioned")
	}
	for _, u := range c.Unparsed {
		sb.WriteString("; ")
		sb.WriteString(u)
	}
	return sb.String()
}

// IsSession reports whether the cookie has neither Expires nor Max-Age and
// so lasts for the browser session.
func (c SetCookie) IsSession() bool {
	return c.Expires.IsZero() && c.RawExpires == "" && c.MaxAge == 0
}

// ExpiresAt returns when the cookie expires, given the time it was
// received. Max-Age takes precedence over Expires, as RFC 6265 §5.3
// requires. ok is false for a session cookie or an unparseable Expires.
func (c SetCookie) ExpiresAt(received time.Time) (t time.Time, ok bool) {
	switch {
	case c.MaxAge < 0:
		return received, true
	case c.MaxAge > 0:
		return received.Add(time.Duration(c.MaxAge) * time.Second), true
	case !c.Expires.IsZero():
		return c.Expires, true
	}
	return time.Time{}, false
}

// ToStd converts the cookie to its net/http equivalent. Unparsed attributes
// and Partitioned are carried in http.Cookie.Unparsed.
func (c SetCookie) ToStd() *http.Cookie {
	std := &http.Cookie{
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		Raw:        c.Raw,
		Unparsed:   append([]string(nil), c.Unparsed...),
	}
	switch c.SameSite {
	case SameSiteLax:
		std.SameSite = http.SameSiteLaxMode
	case SameSiteStrict:
		std.SameSite = http.SameSiteStrictMode
	case SameSiteNone:
		std.SameSite = http.SameSiteNoneMode
	}
	if c.Partitioned {
		std.Partitioned = true
	}
	return std
}

// Validate reports why a user agent following RFC 6265 and its successor
// draft (RFC 6265bis) would reject or alter the cookie. It returns nil when
// the cookie is well formed. Several problems are joined into one error;
// use errors.Is with the Err* values or unwrap it to see each one.
func (c SetCookie) Validate() error {
	var errs []error
	if c.Name == "" {
		errs = append(errs, ErrCookieName)
	} else if !ascii.IsToken(c.Name) {
		errs = append(errs, fmt.Errorf("%w: %q is not a token", ErrCookieName, c.Name))
	}
	if !validCookieValue(c.Value) {
		errs = append(errs, ErrCookieValue)
	}
	if len(c.Name)+len(c.Value) > maxCookieBytes {
		errs = append(errs, ErrCookieTooLong)
	}
	if c.Path != "" && c.Path[0] != '/' {
		errs = append(errs, ErrCookiePath)
	}
	if c.Domain != "" && !validCookieDomain(c.Domain) {
		errs = append(errs, ErrCookieDomain)
	}
	if c.RawExpires != "" && c.Expires.IsZero() {
		errs = append(errs, ErrCookieExpires)
	}
	if c.SameSite == SameSiteNone && !c.Secure {
		errs = append(errs, ErrCookieSameSiteNone)
	}
	if c.Partitioned && !c.Secure {
		errs = append(errs, ErrCookiePartitioned)
	}
	switch {
	case strings.HasPrefix(c.Name, "__Host-"):
		if !c.Secure || c.Domain != "" || c.Path != "/" {
			errs = append(errs, ErrCookieHostPrefix)
		}
	case strings.HasPrefix(c.Name, "__Secure-"):
		if !c.Secure {
			errs = append(errs, ErrCookieSecurePrefix)
		}
	}
	return errors.Join(errs...)
}

// Errors returned by SetCookie.Validate. Each wraps ErrMalformed.
var (
	ErrCookieName         error = &malformedError{"cookie: name is empty or not a token"}
	ErrCookieValue        error = &malformedError{"cookie: value contains characters outside cookie-octet"}
	ErrCookieTooLong      error = &malformedError{"cookie: name and value exceed 4096 bytes"}
	ErrCookiePath         error = &malformedError{"cookie: Path does not start with '/'"}
	ErrCookieDomain       error = &malformedError{"cookie: Domain is not a valid host"}
	ErrCookieExpires      error = &malformedError{"cookie: Expires is not a valid date"}
	ErrCookieSameSiteNone error = &malformedError{"cookie: SameSite=None requires Secure"}
	ErrCookiePartitioned  error = &malformedError{"cookie: Partitioned requires Secure"}
	ErrCookieHostPrefix   error = &malformedError{"cookie: __Host- prefix requires Secure, Path=/ and no Domain"}
	ErrCookieSecurePrefix error = &malformedError{"cookie: __Secure- prefix requires Secure"}
)

// maxCookieBytes is the smallest name+value size RFC 6265bis §5.5 requires
// user agents to accept; browsers reject anything larger.
const maxCookieBytes = 4096

// validCookieValue implements cookie-value from RFC 6265 §4.1.1: a run of
// cookie-octets, optionally wrapped in double quotes.
func validCookieValue(v string) bool {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
		if c < 0x21 || c == '"' || c == ',' || c == ';' || c == '\\' || c > 0x7e {
			return false
		}
	}
	return true
}

// validCookieDomain accepts what RFC 6265 §5.2.3 keeps after stripping a
// leading dot: a host name made of letters, digits, hyphens and dots.
func validCookieDomain(d string) bool {
	d = strings.TrimPrefix(d, ".")
	if d == "" || len(d) > 253 {
		return false
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			letter := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
			if !letter && !ascii.IsDigit(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

// ParseCookieDate parses a cookie Expires value using the algorithm of
// RFC 6265 §5.1.1, which accepts every date format servers have sent in
// practice ("Wed, 21 Oct 2015 07:28:00 GMT", "Wed, 21-Oct-2015 07:28:00
// GMT", "Wed Oct 21 07:28:00 2015" and so on). The result is in UTC. ok is
// false when the value is not a date.
func ParseCookieDate(s string) (t time.Time, ok bool) {
	var (
		hour, minute, second, day, month, year     int
		foundTime, foundDay, foundMonth, foundYear bool
	)
	for tok := range cookieDateTokens(s) {
		switch {
		case !foundTime && parseHMS(tok, &hour, &minute, &second):
			foundTime = true
		case !foundDay && parseDigits(tok, 1, 2, &day):
			foundDay = true
		case !foundMonth && parseMonth(tok, &month):
			foundMonth = true
		case !foundYear && parseDigits(tok, 2, 4, &year):
			foundYear = true
		}
	}
	if !foundTime || !foundDay || !foundMonth || !foundYear {
		return time.Time{}, false
	}
	switch {
	case year >= 70 && year <= 99:
		year += 1900
	case year <= 69:
		year += 2000
	}
	if day < 1 || day > 31 || year < 1601 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	t = time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	if t.Day() != day { // e.g. 31 February normalized into March
		return time.Time{}, false
	}
	return t, true
}

// cookieDateTokens splits s on the delimiter set of RFC 6265 §5.1.1.
func cookieDateTokens(s string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		start := -1
		for i := 0; i <= len(s); i++ {
			delim := i == len(s) || isCookieDateDelim(s[i])
			switch {
			case delim && start >= 0:
				if !yield(s[start:i]) {
					return
				}
				start = -1
			case !delim && start < 0:
				start = i
			}
		}
	}
}

func isCookieDateDelim(c byte) bool {
	return c == 0x09 || (c >= 0x20 && c <= 0x2f) || (c >= 0x3b && c <= 0x40) ||
		(c >= 0x5b && c <= 0x60) || (c >= 0x7b && c <= 0x7e)
}

// parseDigits matches min to max leading digits followed by a non-digit or
// the end of the token.
func parseDigits(tok string, minDigits, maxDigits int, out *int) bool {
	n := 0
	for n < len(tok) && ascii.IsDigit(tok[n]) {
		n++
	}
	if n < minDigits || n > maxDigits {
		return false
	}
	v, err := strconv.Atoi(tok[:n])
	if err != nil {
		return false
	}
	*out = v
	return true
}

// parseHMS matches hh:mm:ss (one or two digits each) followed by a
// non-digit or the end of the token.
func parseHMS(tok string, h, m, s *int) bool {
	var parts [3]int
	i := 0
	for p := range 3 {
		n := 0
		for i+n < len(tok) && ascii.IsDigit(tok[i+n]) {
			n++
		}
		if n < 1 || n > 2 {
			return false
		}
		parts[p], _ = strconv.Atoi(tok[i : i+n])
		i += n
		if p < 2 {
			if i >= len(tok) || tok[i] != ':' {
				return false
			}
			i++
		}
	}
	if i < len(tok) && ascii.IsDigit(tok[i]) {
		return false
	}
	*h, *m, *s = parts[0], parts[1], parts[2]
	return true
}

var monthNames = [...]string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}

func parseMonth(tok string, out *int) bool {
	if len(tok) < 3 {
		return false
	}
	for i, m := range monthNames {
		if ascii.EqualFold(tok[:3], m) {
			*out = i + 1
			return true
		}
	}
	return false
}
