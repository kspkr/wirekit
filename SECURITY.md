# Security policy

WireKit exists to be pointed at untrusted network data, so bugs in how it
handles that data are security bugs.

## Reporting

Please **do not** open a public issue for a vulnerability. Use GitHub's
private vulnerability reporting on this repository ("Security" tab, then
"Report a vulnerability"). Include what you found, how to reproduce it
(a fuzz input or a short test is ideal), and the version or commit.

You will get an acknowledgement within a few days. We will agree on a
disclosure date with you once a fix is ready, and credit you unless you
would rather we did not.

## What counts

We especially want to hear about anything that lets input:

- make a parser **panic** (index out of range, nil dereference, integer
  conversion, and so on);
- make WireKit **allocate or work without bound**: a size limit that can be
  bypassed, a decompression bomb that gets past `compress`, a header or
  frame length that is trusted before it is checked;
- be **interpreted differently** than a browser, server or proxy would in a
  way that matters, for example a request-smuggling-relevant framing
  ambiguity that WireKit resolves silently;
- produce **incorrect security-relevant output**, such as a certificate
  summary that misreports validity or a cookie `Validate` that passes an
  attribute a browser rejects.

Leniency by itself is not a bug: WireKit deliberately parses malformed
input so inspectors can show it. Leniency that *hides* a problem from
`Validate`, or that causes one of the issues above, is.

## Supported versions

Until 1.0, only the latest release receives fixes.
