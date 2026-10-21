// Package jevproxy is a root-owned loopback proxy that holds the
// OpenRouter API key for Jev calls, so no agent-uid component ever does.
//
// It listens on a Unix socket in a root-owned runtime directory, mode
// 0660, group the configured caller group: a caller authenticates by
// connecting, with no key or header of its own (DefaultSocket,
// DefaultCallerGroup). The proxy forwards the caller's path and body
// unchanged to a pinned upstream base URL (DefaultUpstream,
// https://openrouter.ai), adding its own Authorization header from a
// root-owned key file it alone reads (see LoadKey). It refuses to dial any
// host other than the pinned upstream, never follows a redirect the
// upstream sends, and bounds every request and response by size and by
// time so a hung or flooding peer cannot hold the proxy or its caller.
//
// The key is never logged, exported or echoed: every place a caller- or
// upstream-supplied value could reach a log line is wrapped in [Secret],
// whose formatting always prints "[REDACTED]".
//
// A caller that wants to be sure it is talking to the real, root-owned
// proxy rather than a same-uid impostor that raced it to the socket (the
// listener-uid pin pattern from data/barmkin-successor-systemone-proxy-scout/report.md)
// dials with [DialPinned], which checks the listening process's kernel
// peer credentials (SO_PEERCRED) before trusting the connection.
package jevproxy
