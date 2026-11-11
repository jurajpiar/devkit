package runcguard

import (
	"errors"
	"time"
)

// SetupBound is how long the guard waits, after runsc create returns, for
// the gofer and the sandbox to finish making their mount tables. On a real
// VM both were final within 1 to 9 ms of create returning
// (spikes/gvisor/results/09-gofer-timing.log); five seconds is a margin of
// several hundred times that for a VM under load, and still short next to
// the time a person waits for a container before suspecting it.
const SetupBound = 5 * time.Second

// pollInterval is how often a table is read while waiting: a few reads of
// a small file per millisecond-scale setup.
const pollInterval = 2 * time.Millisecond

// errNotFinal is a mount table that never reached its final form.
var errNotFinal = errors.New("not in its final form")

// clock is the time the guard waits by, replaceable for tests.
type clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }

// awaitFinal reads a mount table until final says it is in its final form,
// and returns judge's verdict on that table: a table is judged only once it
// is final, and the first final table is the one judged, passing or not,
// since waiting longer could only give a refused table time to change. A
// table that is still final-less when bound has passed is errNotFinal; with
// a bound of 0 the table is read once. An error from read ends the wait.
func awaitFinal(read func() ([]MountEntry, error), final func([]MountEntry) bool,
	judge func([]MountEntry) *MountEntry, c clock, bound time.Duration) (*MountEntry, error) {
	deadline := c.Now().Add(bound)
	for {
		t, err := read()
		if err != nil {
			return nil, err
		}
		if final(t) {
			return judge(t), nil
		}
		if !c.Now().Before(deadline) {
			return nil, errNotFinal
		}
		c.Sleep(pollInterval)
	}
}
