package screen

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Daviey/barmkin/internal/proto"
)

// golden.json is barmkin-mod's own TypeScript screen run over recorded mock
// Jev responses (testdata/golden.gen.ts). These tests replay it against the
// Go port: the same windows must give the same decision, scores, gap and
// legs. Every endpoint here is an httptest server; no test calls Jev.

type golden struct {
	Model    string              `json:"model"`
	Texts    map[string]textSpec `json:"texts"`
	Plans    []goldenPlan        `json:"plans"`
	Parses   []goldenParse       `json:"parses"`
	Requests []goldenRequest     `json:"requests"`
	Screens  []goldenScreen      `json:"screens"`
	built    map[string]string   // each text, rebuilt from its spec
}

type textSpec struct {
	Repeat *string  `json:"repeat"`
	Pieces []string `json:"pieces"`
	N      int      `json:"n"`
	Seed   uint32   `json:"seed"`
	SHA256 string   `json:"sha256"`
}

type goldenPlan struct {
	Text    string   `json:"text"`
	Windows []Window `json:"windows"`
	Covered int      `json:"covered"`
}

type goldenParse struct {
	Name    string             `json:"name"`
	Body    string             `json:"body"`
	OK      bool               `json:"ok"`
	Answers map[string]float64 `json:"answers"`
	Model   *string            `json:"model"`
}

type goldenRequest struct {
	Set  string `json:"set"`
	Body any    `json:"body"`
}

// mock is one recorded endpoint response.
type mock struct {
	Status  int    `json:"status"`
	Body    string `json:"body"`
	Timeout bool   `json:"timeout"`
	Network bool   `json:"network"`
}

type goldenScreen struct {
	Name       string               `json:"name"`
	Source     proto.Source         `json:"source"`
	Text       string               `json:"text"`
	Configured bool                 `json:"configured"`
	Local      proto.Scores         `json:"local"`
	Production [][]mock             `json:"production"`
	Calls      []int                `json:"calls"`
	Shadow     map[ShadowArm][]mock `json:"shadow"`
	WantShadow []goldenShadowArm    `json:"want_shadow"`
	Want       struct {
		Decision proto.ScreenDecision `json:"decision"`
		Scores   proto.Scores         `json:"scores"`
		Reason   Reason               `json:"reason"`
		Gap      proto.Gap            `json:"gap"`
		Raised   proto.Legs           `json:"raised"`
	} `json:"want"`
}

type goldenShadowArm struct {
	Arm      ShadowArm          `json:"arm"`
	Windows  int                `json:"windows"`
	Answered int                `json:"answered"`
	Scores   map[string]float64 `json:"scores"`
}

func loadGolden(t *testing.T) *golden {
	t.Helper()
	data, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}
	g.built = map[string]string{}
	for name, spec := range g.Texts {
		text := spec.build()
		sum := sha256.Sum256([]byte(text))
		if hex.EncodeToString(sum[:]) != spec.SHA256 {
			t.Fatalf("text %q does not rebuild to its recorded SHA-256", name)
		}
		g.built[name] = text
	}
	return &g
}

// build is golden.gen.ts's build: the same seeded PRNG over UTF-16 units.
func (s textSpec) build() string {
	if s.Repeat != nil {
		return strings.Repeat(*s.Repeat, s.N)
	}
	pieces := make([][]uint16, len(s.Pieces))
	for i, p := range s.Pieces {
		pieces[i] = utf16.Encode([]rune(p))
	}
	state := s.Seed
	var out []uint16
	for len(out) < s.N {
		state = state*1664525 + 1013904223
		out = append(out, pieces[int(math.Floor(float64(state)/(1<<32)*float64(len(pieces))))]...)
	}
	out = out[:s.N]
	if last := out[len(out)-1]; last >= 0xd800 && last <= 0xdbff {
		out[len(out)-1] = '.'
	}
	return string(utf16.Decode(out))
}

func TestGoldenWindowPlans(t *testing.T) {
	g := loadGolden(t)
	for _, want := range g.Plans {
		p := PlanWindows(g.built[want.Text])
		if !reflect.DeepEqual(p.Windows, want.Windows) || p.Covered != want.Covered {
			t.Errorf("%s: windows %v covered %d, want %v covered %d", want.Text, p.Windows, p.Covered, want.Windows, want.Covered)
			continue
		}
		for i, w := range p.Texts {
			if n := utf16Len(w); n != want.Windows[i].End-want.Windows[i].Start {
				t.Errorf("%s: window %d text is %d units", want.Text, i, n)
			}
		}
	}
}

func TestGoldenParse(t *testing.T) {
	g := loadGolden(t)
	for _, want := range g.Parses {
		a := parseResponse([]byte(want.Body), ProductionQuestionIDs)
		if a.OK() != want.OK {
			t.Errorf("%s: ok = %v, want %v", want.Name, a.OK(), want.OK)
			continue
		}
		if want.OK && (!reflect.DeepEqual(a.Answers, want.Answers) || a.Model != *want.Model) {
			t.Errorf("%s: %v %q, want %v %q", want.Name, a.Answers, a.Model, want.Answers, *want.Model)
		}
		if !want.OK && a.Failure != FailureMalformed {
			t.Errorf("%s: failure %q, want malformed", want.Name, a.Failure)
		}
	}
}

func TestGoldenRequests(t *testing.T) {
	g := loadGolden(t)
	sets := map[string]*QuestionSet{"production": ProductionQuestions, "captain": ShadowQuestions(ArmCaptain), "revised": ShadowQuestions(ArmRevised)}
	for _, want := range g.Requests {
		data, err := json.Marshal(buildRequest(g.Model, g.built["short"], sets[want.Set]))
		if err != nil {
			t.Fatal(err)
		}
		var got any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want.Body) {
			t.Errorf("%s request differs:\n got %v\nwant %v", want.Set, got, want.Body)
		}
	}
}

// mockJev serves recorded responses, by question set and window text, and
// counts each window's production calls.
type mockJev struct {
	t          *testing.T
	windows    map[string]int
	production [][]mock
	shadow     map[ShadowArm][]mock
	credential string

	mu    sync.Mutex
	calls map[string][]int // set -> per-window calls
}

func newMockJev(t *testing.T, windows []string, production [][]mock, shadow map[ShadowArm][]mock, credential string) (*mockJev, *httptest.Server) {
	m := &mockJev{t: t, windows: map[string]int{}, production: production, shadow: shadow, credential: credential, calls: map[string][]int{}}
	for i, w := range windows {
		m.windows[w] = i
	}
	for _, set := range []string{"production", "captain", "revised"} {
		m.calls[set] = make([]int, len(windows))
	}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return m, srv
}

func (m *mockJev) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req systemOneRequest
	if r.Method != http.MethodPost || r.URL.Path != SystemOnePath || json.NewDecoder(r.Body).Decode(&req) != nil {
		m.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+m.credential {
		m.t.Errorf("Authorization = %q", got)
	}
	set := map[int]string{3: "production", 4: "captain", 1: "revised"}[len(req.Questions)]
	i, ok := m.windows[req.State["content"]]
	if set == "" || !ok {
		m.t.Errorf("request for an unknown set or window (%d questions)", len(req.Questions))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	n := m.calls[set][i]
	m.calls[set][i]++
	m.mu.Unlock()
	var resp mock
	switch {
	case set == "production" && n < len(m.production[i]):
		resp = m.production[i][n]
	case set != "production" && m.shadow != nil && n == 0:
		resp = m.shadow[ShadowArm(set)][i]
	default:
		m.t.Errorf("%s window %d asked %d times", set, i, n+1)
		w.WriteHeader(http.StatusTeapot)
		return
	}
	switch {
	case resp.Timeout:
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	case resp.Network:
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	default:
		w.WriteHeader(resp.Status)
		w.Write([]byte(resp.Body))
	}
}

func (m *mockJev) productionCalls() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls["production"])
}

func TestGoldenScreens(t *testing.T) {
	g := loadGolden(t)
	const credential = "test-credential"
	for _, c := range g.Screens {
		t.Run(c.Name, func(t *testing.T) {
			plan := PlanWindows(g.built[c.Text])
			cfg := Config{Timeout: 100 * time.Millisecond}
			var m *mockJev
			if c.Configured {
				var srv *httptest.Server
				m, srv = newMockJev(t, plan.Texts, c.Production, c.Shadow, credential)
				cfg.Endpoint, cfg.Credential, cfg.Model = srv.URL, credential, g.Model
			}
			var shadow []ShadowReport
			if c.Shadow != nil {
				cfg.Shadow = func(r ShadowReport) { shadow = append(shadow, r) }
			}
			s, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Screen(context.Background(), Input{Source: c.Source, Windows: plan.Texts, PastLastWindow: plan.PastLastWindow(), Local: c.Local})
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision != c.Want.Decision || got.Scores != c.Want.Scores || got.Reason != c.Want.Reason ||
				got.Gap != c.Want.Gap || got.Raised != c.Want.Raised {
				t.Errorf("outcome %+v\nwant %+v", got, c.Want)
			}
			if m != nil {
				if calls := m.productionCalls(); !reflect.DeepEqual(calls, c.Calls) {
					t.Errorf("production calls per window %v, want %v", calls, c.Calls)
				}
			}
			if c.WantShadow == nil {
				return
			}
			if len(shadow) != 1 {
				t.Fatalf("%d shadow reports, want 1", len(shadow))
			}
			for i, want := range c.WantShadow {
				arm := shadow[0].Arms[i]
				if arm.Arm != want.Arm || arm.Windows != want.Windows || arm.Answered != want.Answered || !reflect.DeepEqual(arm.Scores, want.Scores) {
					t.Errorf("shadow arm %+v, want %+v", arm, want)
				}
			}
		})
	}
}
