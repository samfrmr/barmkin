package screen

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"sync"
	"time"
)

// Cache defaults.
const (
	DefaultCacheTTL     = 24 * time.Hour
	DefaultCacheEntries = 4096
)

// cacheKey names one window's answer to one question set from one model:
// SHA-256 over the question set's SHA-256, the pinned model id and the
// redacted window text, each length-prefixed. A wording or model change
// therefore misses every earlier entry by construction.
type cacheKey [sha256.Size]byte

func newCacheKey(qs *QuestionSet, model, window string) cacheKey {
	h := sha256.New()
	for _, part := range []string{qs.SHA256, model, window} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	var k cacheKey
	h.Sum(k[:0])
	return k
}

type cacheEntry struct {
	key     cacheKey
	answer  Answer
	expires time.Time
}

// cache is a bounded, least-recently-used map from a window to its parsed
// answer: the scores only, never a session decision, which each screen
// still makes from them. Only answers are stored; a failure is never
// cached, so an outage is re-asked rather than remembered. Entries live for
// ttl, and the least recently used is evicted past max entries; an
// eviction only costs a re-ask.
//
// The cache has no query endpoint: it is reachable only through a screen,
// which re-applies the cached answer to the calling session. The shadow
// screen has its own cache, so it can never fill or read production's.
type cache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	order *list.List // front is most recently used
	items map[cacheKey]*list.Element
}

func newCache(ttl time.Duration, entries int) *cache {
	return &cache{ttl: ttl, max: entries, order: list.New(), items: map[cacheKey]*list.Element{}}
}

func (c *cache) get(now time.Time, k cacheKey) (Answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return Answer{}, false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.order.Remove(el)
		delete(c.items, k)
		return Answer{}, false
	}
	c.order.MoveToFront(el)
	return copyAnswer(e.answer), true
}

// put stores an answer. A failure is refused.
func (c *cache) put(now time.Time, k cacheKey, a Answer) {
	if !a.OK() || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := &cacheEntry{key: k, answer: copyAnswer(a), expires: now.Add(c.ttl)}
	if el, ok := c.items[k]; ok {
		el.Value = e
		c.order.MoveToFront(el)
		return
	}
	c.items[k] = c.order.PushFront(e)
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*cacheEntry).key)
	}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func copyAnswer(a Answer) Answer {
	a.Answers = maps.Clone(a.Answers)
	return a
}
