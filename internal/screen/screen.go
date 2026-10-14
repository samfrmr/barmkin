package screen

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Daviey/barmkin/internal/proto"
)

// Defaults for a Config field left zero.
const (
	DefaultModel   = "jev-1.13.0"
	DefaultTimeout = 700 * time.Millisecond
)

// ErrInvalidInput is returned for an Input the screen refuses.
var ErrInvalidInput = errors.New("screen: invalid input")

// Credential is the Jev endpoint's bearer credential. It is part of the
// monitor's own configuration, never a plugin's user configuration, and it
// formats as [REDACTED] so it cannot reach a log or a status line.
type Credential string

func (c Credential) String() string {
	if c == "" {
		return ""
	}
	return "[REDACTED]"
}

func (c Credential) GoString() string { return `screen.Credential("` + c.String() + `")` }

func (c Credential) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Config is the screen's part of the monitor configuration.
type Config struct {
	// Endpoint is the Jev System One base URL, for example
	// https://gateway.example/api. Empty means Jev is not configured: every
	// screen uses the shim's local scores and reports no gap. It must be
	// https, or http to a loopback address, with no user info, query or
	// fragment.
	Endpoint string
	// Model is the pinned model id sent with each request. Default
	// DefaultModel.
	Model string
	// Credential is sent as a bearer token to Endpoint only.
	Credential Credential
	// Timeout bounds each call. Default DefaultTimeout. A window that fails
	// for a transient reason is asked once more, so a screen waits at most
	// about twice this.
	Timeout time.Duration
	// CacheTTL and CacheEntries bound the production cache; ShadowCacheEntries
	// bounds the shadow screen's. Defaults DefaultCacheTTL and
	// DefaultCacheEntries. A negative entry count disables that cache.
	CacheTTL           time.Duration
	CacheEntries       int
	ShadowCacheEntries int
	// BreakerThreshold and BreakerCooldown tune the endpoint's breakers.
	// Defaults DefaultBreakerThreshold and DefaultBreakerCooldown.
	BreakerThreshold int
	BreakerCooldown  time.Duration
	// Shadow, when set, turns on the shadow screen and receives each of its
	// reports. The shadow screen is contrast instrumentation: it never
	// affects an Outcome.
	Shadow func(ShadowReport)
	// Transport carries the requests. Default a clone of
	// http.DefaultTransport.
	Transport http.RoundTripper
}

// Input is one piece of untrusted content to screen: the shim's
// already-redacted window plan, its local heuristic scores and the source
// the content came from.
type Input struct {
	Source proto.Source
	// Windows are the redacted windows, in order: 1 to MaxWindows of 1 to
	// WindowChars UTF-16 code units.
	Windows []string
	// PastLastWindow is true when the redacted content ran past the last
	// window, so part of it is never classified.
	PastLastWindow bool
	// Local are the shim's own scores, for example its injection heuristic
	// and its secret scan.
	Local proto.Scores
}

// ShadowReport is what the shadow screen answered for one piece of
// content, per arm. Annotation only: nothing decides, taints or withholds
// on it.
type ShadowReport struct {
	Arms []ShadowArmReport
}

// ShadowArmReport is one arm's answers merged over its windows.
type ShadowArmReport struct {
	Arm      ShadowArm
	Windows  int
	Answered int
	Scores   map[string]float64 // each question's highest answer; empty when none answered
}

// Screener screens untrusted content against one Jev endpoint. It is safe
// for concurrent use: its breakers and caches are shared by every session,
// which is the honest model of one endpoint.
type Screener struct {
	client        *systemOneClient // nil when Jev is not configured
	prodBreaker   *breaker
	shadowBreaker *breaker
	prodCache     *cache
	shadowCache   *cache
	shadow        func(ShadowReport)
	now           func() time.Time
}

// New returns a Screener for cfg.
func New(cfg Config) (*Screener, error) {
	s := &Screener{shadow: cfg.Shadow, now: time.Now}
	threshold := orDefault(cfg.BreakerThreshold, DefaultBreakerThreshold)
	cooldown := orDefault(cfg.BreakerCooldown, DefaultBreakerCooldown)
	s.prodBreaker = &breaker{threshold: threshold, cooldown: cooldown}
	s.shadowBreaker = &breaker{threshold: threshold, cooldown: cooldown}
	ttl := orDefault(cfg.CacheTTL, DefaultCacheTTL)
	s.prodCache = newCache(ttl, orDefault(cfg.CacheEntries, DefaultCacheEntries))
	s.shadowCache = newCache(ttl, orDefault(cfg.ShadowCacheEntries, DefaultCacheEntries))
	if cfg.Endpoint == "" {
		if cfg.Credential != "" {
			return nil, errors.New("screen: a credential without an endpoint")
		}
		return s, nil
	}
	base, err := checkEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	s.client = &systemOneClient{
		url:        base + SystemOnePath,
		model:      orDefault(cfg.Model, DefaultModel),
		credential: cfg.Credential,
		timeout:    orDefault(cfg.Timeout, DefaultTimeout),
		http:       &http.Client{Transport: transport, CheckRedirect: noRedirect},
	}
	return s, nil
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// checkEndpoint returns the endpoint without trailing slashes, or an error
// when it could send the credential somewhere other than intended.
func checkEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("screen: the endpoint must be an absolute URL with no user info, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return "", errors.New("screen: an http endpoint must be a loopback address")
		}
	default:
		return "", errors.New("screen: the endpoint must be https")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Configured reports whether a Jev endpoint is configured.
func (s *Screener) Configured() bool { return s.client != nil }

// State is the classifier's state for status: degraded when Jev is not
// configured or its breaker is open, so screens use local scores only.
func (s *Screener) State() proto.ClassifierState {
	if s.client == nil || s.prodBreaker.open(s.now()) {
		return proto.ClassifierDegraded
	}
	return proto.ClassifierOK
}

// Screen scores one piece of content and decides. It returns an error only
// for an invalid Input; an endpoint failure is never an error, and never a
// pass: the window is unanswered, the local scores stand, and the
// classifier-gap rule applies. Neither the content nor the endpoint's text
// reaches the Outcome.
func (s *Screener) Screen(ctx context.Context, in Input) (Outcome, error) {
	if !validInput(in) {
		return Outcome{}, ErrInvalidInput
	}
	results := make([]Answer, len(in.Windows))
	for i := range results {
		results[i] = Answer{Failure: failureUnasked}
	}
	if s.client != nil {
		var wg sync.WaitGroup
		var report *ShadowReport
		now := s.now()
		if s.shadow != nil && !s.prodBreaker.open(now) && !s.shadowBreaker.open(now) {
			wg.Go(func() { report = s.screenShadow(ctx, in.Windows) })
		}
		s.screenProduction(ctx, in.Windows, results)
		wg.Wait()
		if report != nil {
			s.shadow(*report)
		}
	}

	var jev *jevScores
	if merged, _, ok := mergeAnswers(results, ProductionQuestionIDs); ok {
		jev = &jevScores{
			injection:    merged[QuestionInjection],
			exfiltration: merged[QuestionExfiltration],
			credentials:  merged[QuestionCredentials],
		}
	}
	answered := make([]bool, len(results))
	for i, r := range results {
		answered[i] = r.OK()
	}
	gap := classifierGap(s.client != nil, in.PastLastWindow, answered)
	return composeOutcome(in.Source, in.Local, jev, gap), nil
}

// failureUnasked marks a window the screen did not ask: Jev is not
// configured or its breaker is open.
const failureUnasked Failure = "unasked"

// screenProduction fills results from the cache, then asks every other
// window at once while the breaker is closed, and once more each window
// that failed for a transient reason. It counts one breaker event for the
// windows it asked, however many there were, unless the caller gave up.
func (s *Screener) screenProduction(ctx context.Context, windows []string, results []Answer) {
	var pending []int
	for i, w := range windows {
		if a, ok := s.prodCache.get(s.now(), newCacheKey(ProductionQuestions, s.client.model, w)); ok {
			results[i] = a
		} else {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 || s.prodBreaker.open(s.now()) {
		return
	}
	s.askAll(ctx, windows, pending, ProductionQuestions, results)
	var retry []int
	for _, i := range pending {
		if results[i].transient() {
			retry = append(retry, i)
		}
	}
	s.askAll(ctx, windows, retry, ProductionQuestions, results)
	ok := true
	for _, i := range pending {
		if results[i].OK() {
			s.prodCache.put(s.now(), newCacheKey(ProductionQuestions, s.client.model, windows[i]), results[i])
		} else {
			ok = false
		}
	}
	if ctx.Err() == nil {
		s.prodBreaker.record(s.now(), ok)
	}
}

// askAll asks the windows named by idx in parallel, into results.
func (s *Screener) askAll(ctx context.Context, windows []string, idx []int, qs *QuestionSet, results []Answer) {
	var wg sync.WaitGroup
	for _, i := range idx {
		wg.Go(func() { results[i] = s.client.ask(ctx, windows[i], qs) })
	}
	wg.Wait()
}

// screenShadow asks every window once per shadow arm, in parallel with the
// production screen and bounded by the same timeout. No retry: a shadow
// answer is never worth a second request. It has its own breaker and its
// own cache, so it can neither degrade nor fill the production screen.
func (s *Screener) screenShadow(ctx context.Context, windows []string) *ShadowReport {
	perArm := make([][]Answer, len(ShadowArms))
	asked, ok := false, true
	for a, arm := range ShadowArms {
		qs := shadowQuestions[arm]
		perArm[a] = make([]Answer, len(windows))
		var pending []int
		for i, w := range windows {
			if ans, hit := s.shadowCache.get(s.now(), newCacheKey(qs, s.client.model, w)); hit {
				perArm[a][i] = ans
			} else {
				pending = append(pending, i)
			}
		}
		s.askAll(ctx, windows, pending, qs, perArm[a])
		for _, i := range pending {
			asked = true
			if perArm[a][i].OK() {
				s.shadowCache.put(s.now(), newCacheKey(qs, s.client.model, windows[i]), perArm[a][i])
			} else {
				ok = false
			}
		}
	}
	if asked && ctx.Err() == nil {
		s.shadowBreaker.record(s.now(), ok)
	}
	report := &ShadowReport{}
	for a, arm := range ShadowArms {
		merged, answered, _ := mergeAnswers(perArm[a], shadowQuestions[arm].IDs)
		if merged == nil {
			merged = map[string]float64{}
		}
		report.Arms = append(report.Arms, ShadowArmReport{Arm: arm, Windows: len(windows), Answered: answered, Scores: merged})
	}
	return report
}

// validInput holds an Input to the screen request's contract.
func validInput(in Input) bool {
	switch in.Source {
	case proto.SourceMCP, proto.SourceFetch, proto.SourceRead, proto.SourcePeer, proto.SourceSkill, proto.SourceInvisible:
	default:
		return false
	}
	if len(in.Windows) == 0 || len(in.Windows) > MaxWindows {
		return false
	}
	for _, w := range in.Windows {
		if n := utf16Len(w); n == 0 || n > WindowChars {
			return false
		}
	}
	for _, p := range []float64{in.Local.Injection, in.Local.Credentials, in.Local.Exfiltration} {
		if !(p >= 0 && p <= 1) {
			return false
		}
	}
	return true
}
