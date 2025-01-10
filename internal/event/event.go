package event

type BaseEvent struct {
	Type        string `json:"type"`
	ProcessInfo struct {
		Comm string `json:"comm"`
		PID  int    `json:"pid"`
	} `json:"process"`
}
