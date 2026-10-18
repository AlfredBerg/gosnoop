package filter

import (
	"testing"

	"gosnoop/internal/event"
)

func ev(pid int, comm string, parents ...int) event.BaseEvent {
	b := event.BaseEvent{}
	b.ProcessInfo.PID = pid
	b.ProcessInfo.Comm = comm
	for _, p := range parents {
		b.ProcessInfo.Parents = append(b.ProcessInfo.Parents, event.Process{PID: p})
	}
	return b
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name  string
		f     Filter
		e     event.BaseEvent
		match bool
	}{
		{"empty filter keeps everything", Filter{}, ev(10, "curl"), true},
		{"pid match", Filter{PIDs: map[int]bool{10: true}}, ev(10, "curl"), true},
		{"pid mismatch", Filter{PIDs: map[int]bool{11: true}}, ev(10, "curl"), false},
		{"pid does not match ancestors", Filter{PIDs: map[int]bool{5: true}}, ev(10, "curl", 5), false},
		{"pid-tree matches the process itself", Filter{TreePIDs: map[int]bool{10: true}}, ev(10, "curl"), true},
		{"pid-tree matches a descendant", Filter{TreePIDs: map[int]bool{5: true}}, ev(10, "curl", 7, 5), true},
		{"pid-tree mismatch", Filter{TreePIDs: map[int]bool{6: true}}, ev(10, "curl", 7, 5), false},
		{"comm match", Filter{Comms: map[string]bool{"curl": true}}, ev(10, "curl"), true},
		{"comm mismatch", Filter{Comms: map[string]bool{"wget": true}}, ev(10, "curl"), false},
		{"exclude-comm wins", Filter{Comms: map[string]bool{"curl": true}, ExcludeComms: map[string]bool{"curl": true}}, ev(10, "curl"), false},
		{"exclude-pid wins", Filter{PIDs: map[int]bool{10: true}, ExcludePIDs: map[int]bool{10: true}}, ev(10, "curl"), false},
		{"pid and comm are both required", Filter{PIDs: map[int]bool{10: true}, Comms: map[string]bool{"wget": true}}, ev(10, "curl"), false},
		{"pid or pid-tree is enough", Filter{PIDs: map[int]bool{99: true}, TreePIDs: map[int]bool{5: true}}, ev(10, "curl", 5), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Match(tt.e); got != tt.match {
				t.Errorf("Match() = %v, want %v", got, tt.match)
			}
		})
	}
}
