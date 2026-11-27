// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// The same words and pieces as the guard's own test (guard_cross.rs,
// words_do_not_look_random).
func TestLooksRandomMatchesTheGuard(t *testing.T) {
	for _, w := range []string{"billing-service", "Production", "DATABASE_PASSWORD", "20241127", "correct.horse"} {
		if looksRandom(w) {
			t.Errorf("%q looks random", w)
		}
	}
	for _, w := range []string{"aZk2mQ9xP", "ghp_x8Kq", "deadbeef00", "Summer2024", "AKIAQWRTZPLM", `q!x"wr%a`} {
		if !looksRandom(w) {
			t.Errorf("%q does not look random", w)
		}
	}
}

// Every seed kind is cut into pieces the guard sees (at least the minimum
// length, each reading as random) and none of which it counts alone, except
// values too short to cut.
func TestShortPiecesOfEverySeed(t *testing.T) {
	const runs = 200
	uncut := map[leak.Kind]int{}
	defer func() {
		for k, n := range uncut {
			if (k == leak.KindAWSAccessKey && n > runs/3) || (k != leak.KindAWSAccessKey && n > runs/20) {
				t.Errorf("%s: %d of %d values not cut", k, n, runs)
			}
		}
	}()
	for range runs {
		for _, s := range leak.GenerateSet() {
			v := s.Value()
			p := shortPieces(v)
			if strings.Join(p, "") != v {
				t.Fatalf("%s: pieces do not join into the value", s)
			}
			if len(v) < 2*minPiece {
				if len(p) != 1 {
					t.Fatalf("%s: a short value was cut", s)
				}
				continue
			}
			if len(p) == 1 {
				// No cut reads as random: an AWS access key ID's letters
				// between its digits, a password's symbols next to
				// symbols, a random value now and then.
				uncut[s.Kind]++
				continue
			}
			covered := 0
			for i, x := range p {
				last := i == len(p)-1
				if last && len(x) <= min(splitSlack, len(v)/4) {
					continue
				}
				if len(x) < minPiece || !looksRandom(x) {
					t.Fatalf("%s: piece %d of %d bytes does not count", s, i, len(x))
				}
				if 2*len(x) >= len(v) && len(x) < maxFragment {
					t.Fatalf("%s: piece %d is a fragment on its own", s, i)
				}
				covered += len(x)
			}
			if covered+min(splitSlack, len(v)/4) < len(v) {
				t.Fatalf("%s: the pieces leave too much out", s)
			}
		}
	}
}

func TestPiecesLeaked(t *testing.T) {
	seed := leak.NewSeed("t", leak.KindAPIKey, "aB3dE5fG7hJ9kL1mN3pQ5rS7")
	pieces := shortPieces(seed.Value())
	ex := func(bodies ...string) []fp.Exchange {
		var out []fp.Exchange
		for _, b := range bodies {
			out = append(out, fp.Exchange{Capture: leak.Capture{Body: []byte(b)}})
		}
		return out
	}
	if _, ok := piecesLeaked(pieces, ex(`{"a":"`+pieces[0]+`"}`, `{"b":"`+pieces[1]+`","c":"`+pieces[2]+`"}`), seed); !ok {
		t.Error("every piece arrived: not reported")
	}
	if _, ok := piecesLeaked(pieces, ex(`{"a":"`+pieces[0]+`"}`, `{"b":"⟦scrim:k:01⟧","c":"`+pieces[2]+`"}`), seed); ok {
		t.Error("a repaired piece reported as a leak")
	}
	if _, ok := piecesLeaked([]string{seed.Value()}, ex(seed.Value()), seed); ok {
		t.Error("one piece is the checker's job")
	}
}
