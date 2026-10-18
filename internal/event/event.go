package event

type Process struct {
	Comm   string `json:"comm"`
	PID    int    `json:"pid"`
	Cgroup string `json:"cgroup,omitempty"`
}

type ProcessInfo struct {
	Process
	Parents []Process `json:"parents"`
}

type BaseEvent struct {
	Type        string      `json:"type"`
	ProcessInfo ProcessInfo `json:"process"`
}

// Base lets anything embedding BaseEvent satisfy Event.
func (b BaseEvent) Base() BaseEvent {
	return b
}

// Event is implemented by every event a collector emits, so that filtering and
// output do not have to know about the concrete event types.
type Event interface {
	Base() BaseEvent
}
