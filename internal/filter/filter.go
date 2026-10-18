// Package filter narrows the firehose of collected events down to the ones a
// user asked for.
package filter

import "gosnoop/internal/event"

// Filter drops events that do not match the pid and comm selections given on
// the command line. The zero value keeps everything.
type Filter struct {
	// PIDs, when non-empty, keeps only events whose process matches exactly.
	PIDs map[int]bool
	// TreePIDs, when non-empty, keeps events from those processes and from any
	// descendant, matched against the parent stack the probes collect.
	TreePIDs map[int]bool
	// Comms, when non-empty, keeps only events from these command names.
	Comms map[string]bool
	// ExcludePIDs and ExcludeComms drop events regardless of the above.
	ExcludePIDs  map[int]bool
	ExcludeComms map[string]bool
}

// Match reports whether an event should be emitted.
func (f Filter) Match(b event.BaseEvent) bool {
	p := b.ProcessInfo

	if f.ExcludePIDs[p.PID] {
		return false
	}
	if f.ExcludeComms[p.Comm] {
		return false
	}
	if len(f.Comms) > 0 && !f.Comms[p.Comm] {
		return false
	}
	if len(f.PIDs) > 0 || len(f.TreePIDs) > 0 {
		return f.matchPID(p)
	}
	return true
}

func (f Filter) matchPID(p event.ProcessInfo) bool {
	if f.PIDs[p.PID] || f.TreePIDs[p.PID] {
		return true
	}
	for _, parent := range p.Parents {
		if f.TreePIDs[parent.PID] {
			return true
		}
	}
	return false
}
