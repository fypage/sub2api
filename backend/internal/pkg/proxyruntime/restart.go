package proxyruntime

import "time"

type RestartPolicy struct {
	MaxRestarts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func (p RestartPolicy) Delay(restartCount int) (time.Duration, bool) {
	if p.MaxRestarts < 0 || p.MaxRestarts > 20 || p.BaseDelay <= 0 || p.MaxDelay < p.BaseDelay || p.MaxDelay > 10*time.Minute {
		return 0, false
	}
	if restartCount < 0 || restartCount >= p.MaxRestarts {
		return 0, false
	}
	delay := p.BaseDelay
	for attempt := 0; attempt < restartCount; attempt++ {
		if delay >= p.MaxDelay/2 {
			return p.MaxDelay, true
		}
		delay *= 2
	}
	if delay > p.MaxDelay {
		delay = p.MaxDelay
	}
	return delay, true
}
