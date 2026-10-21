package jevproxy

import "time"

// Defaults for the root-managed deployment.
const (
	DefaultSocket      = "/run/barmkin-jevproxy/jevproxy.sock"
	DefaultKeyPath     = "/etc/barmkin/jev-openrouter.key"
	DefaultCallerGroup = "barmkin-jev-clients"
	DefaultUpstream    = "https://openrouter.ai"
	DefaultTimeout     = 10 * time.Second
	// DefaultMaxBodyBytes bounds a request or a response body. OpenRouter
	// chat payloads are small JSON; this is generous without letting a
	// caller or a malicious upstream hold the proxy's memory open.
	DefaultMaxBodyBytes = 1 << 20 // 1 MiB
)

// Config is how a Jev proxy is deployed.
type Config struct {
	Socket       string // the caller socket, in a root-created runtime directory
	KeyPath      string // the root-owned, mode-0600 file holding the OpenRouter API key
	CallerGroup  string // the group whose members may connect; they present no credential
	Upstream     string // the pinned upstream base URL; only https://openrouter.ai is supported today
	Timeout      time.Duration
	MaxBodyBytes int64
	Logf         func(format string, args ...any)
}

// withDefaults returns cfg with every zero field set to its default.
func (cfg Config) withDefaults() Config {
	if cfg.Socket == "" {
		cfg.Socket = DefaultSocket
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = DefaultKeyPath
	}
	if cfg.CallerGroup == "" {
		cfg.CallerGroup = DefaultCallerGroup
	}
	if cfg.Upstream == "" {
		cfg.Upstream = DefaultUpstream
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return cfg
}
