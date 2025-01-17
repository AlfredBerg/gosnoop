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
