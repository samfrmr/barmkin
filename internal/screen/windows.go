package screen

import (
	"unicode/utf16"

	"github.com/Daviey/barmkin/internal/proto"
)

// How redacted untrusted content is cut into the classifier's windows,
// ported from barmkin-mod's hooks/lib/classifier-windows.ts. The shims plan
// the windows and send them to the monitor; the monitor never sees the
// whole text. PlanWindows is here for Go clients and for parity. Offsets
// and lengths are UTF-16 code units, as the shims measure text.

// Window plan bounds.
const (
	// WindowChars is how much one request reads.
	WindowChars = proto.MaxWindowSize
	// WindowOverlap is how many characters consecutive windows share, so
	// any stretch this long or shorter lies whole inside one window.
	WindowOverlap = 512
	// MaxWindows windows cover 4,000 + 4 x 3,488 = 17,952 characters.
	// Text past the last window is never classified.
	MaxWindows = proto.MaxWindows
)

// A window's end moves back by at most boundarySlack characters to land
// after whitespace rather than inside a word.
const boundarySlack = 128

// placeholderMax bounds a [REDACTED:<rule>#<n>] placeholder's length.
const placeholderMax = 48

var placeholderOpen = utf16.Encode([]rune("[REDACTED:"))

// Window is one planned window: UTF-16 offsets into the planned text.
type Window struct {
	Start, End int
}

// Plan is a planned text: its windows and their texts. Covered is where
// the last window ends; text past it is never classified.
type Plan struct {
	Windows []Window
	Texts   []string
	Covered int
	Length  int
}

// PastLastWindow reports whether the text runs past the last window.
func (p Plan) PastLastWindow() bool { return p.Covered < p.Length }

// PlanWindows cuts already-redacted text into windows of at most
// WindowChars characters, each starting WindowOverlap characters before the
// previous one ended, until the text is covered or MaxWindows are planned.
// A cut never splits a placeholder or a surrogate pair.
func PlanWindows(text string) Plan {
	u := utf16.Encode([]rune(text))
	ws := planUnits(u, WindowChars, WindowOverlap, MaxWindows)
	p := Plan{Windows: ws, Length: len(u)}
	for _, w := range ws {
		p.Texts = append(p.Texts, string(utf16.Decode(u[w.Start:w.End])))
	}
	if len(ws) > 0 {
		p.Covered = ws[len(ws)-1].End
	}
	return p
}

func planUnits(u []uint16, size, overlap, limit int) []Window {
	var ws []Window
	start := 0
	for len(ws) < limit {
		end := len(u)
		if start+size < len(u) {
			end = snapCut(u, start+size)
		}
		ws = append(ws, Window{start, end})
		if end >= len(u) {
			break
		}
		start = max(snapStart(u, end-overlap), start+1)
	}
	return ws
}

// snapCut moves a cut back so it falls after whitespace when there is some
// nearby, and never inside a placeholder or between a surrogate pair.
func snapCut(u []uint16, cut int) int {
	c := cut
	for i := cut; i > max(cut-boundarySlack, 0); i-- {
		if jsSpace(u[i-1]) {
			c = i
			break
		}
	}
	if open := lastIndex(u, placeholderOpen, c-1); open != -1 && open > c-placeholderMax {
		if n := placeholderAt(u, open); n > 0 && open+n > c {
			c = open
		}
	}
	if c > 0 && u[c-1] >= 0xd800 && u[c-1] <= 0xdbff {
		c--
	}
	return c
}

// snapStart moves a window's start back so it does not begin inside a
// placeholder or on the second half of a surrogate pair.
func snapStart(u []uint16, start int) int {
	s := start
	if open := lastIndex(u, placeholderOpen, s); open != -1 && open > s-placeholderMax {
		if n := placeholderAt(u, open); n > 0 && open+n > s {
			s = open
		}
	}
	if s >= 0 && s < len(u) && u[s] >= 0xdc00 && u[s] <= 0xdfff {
		s--
	}
	return s
}

// lastIndex is JavaScript's lastIndexOf(sub, from): the last index at or
// before from where sub starts, or -1.
func lastIndex(u, sub []uint16, from int) int {
	for i := min(max(from, 0), len(u)-len(sub)); i >= 0; i-- {
		if hasPrefixAt(u, sub, i) {
			return i
		}
	}
	return -1
}

func hasPrefixAt(u, sub []uint16, i int) bool {
	if i+len(sub) > len(u) {
		return false
	}
	for j := range sub {
		if u[i+j] != sub[j] {
			return false
		}
	}
	return true
}

// placeholderAt returns the length of a /\[REDACTED:[a-z-]+#\d+\]/
// placeholder starting exactly at i, or 0.
func placeholderAt(u []uint16, i int) int {
	if !hasPrefixAt(u, placeholderOpen, i) {
		return 0
	}
	j := i + len(placeholderOpen)
	k := j
	for k < len(u) && ((u[k] >= 'a' && u[k] <= 'z') || u[k] == '-') {
		k++
	}
	if k == j || k >= len(u) || u[k] != '#' {
		return 0
	}
	k++
	d := k
	for k < len(u) && u[k] >= '0' && u[k] <= '9' {
		k++
	}
	if k == d || k >= len(u) || u[k] != ']' {
		return 0
	}
	return k + 1 - i
}

// jsSpace is JavaScript's \s for one UTF-16 code unit.
func jsSpace(c uint16) bool {
	switch {
	case c >= 0x09 && c <= 0x0d, c == 0x20, c == 0xa0, c == 0x1680,
		c >= 0x2000 && c <= 0x200a, c == 0x2028, c == 0x2029, c == 0x202f,
		c == 0x205f, c == 0x3000, c == 0xfeff:
		return true
	}
	return false
}

// UnclassifiedChars counts the characters of a text of length characters
// that no answered window covered: the windows that failed or were not
// asked, and anything past the last window.
func UnclassifiedChars(length int, windows []Window, answered []bool) int {
	covered, reach := 0, 0
	for i, w := range windows {
		if !answered[i] {
			continue
		}
		from := max(w.Start, reach)
		if w.End > from {
			covered += w.End - from
		}
		reach = max(reach, w.End)
	}
	return length - covered
}

// utf16Len is a string's length in UTF-16 code units.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// mergeAnswers takes each question's highest probability over the windows
// that answered. A window that failed contributes nothing: it is never read
// as a 0, so a failure cannot lower a score. ok is false when no window
// answered.
func mergeAnswers(results []Answer, ids []string) (merged map[string]float64, answered int, ok bool) {
	for _, r := range results {
		if !r.OK() {
			continue
		}
		if merged == nil {
			merged = make(map[string]float64, len(ids))
			for _, id := range ids {
				merged[id] = 0
			}
		}
		answered++
		for _, id := range ids {
			merged[id] = max(merged[id], r.Answers[id])
		}
	}
	return merged, answered, merged != nil
}
