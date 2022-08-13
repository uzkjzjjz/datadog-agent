package log

type Logger struct{}

func (l Logger) Warnf(format string, args ...interface{}) {
	Warnf(format, args...)
}

func (l Logger) Debugf(format string, args ...interface{}) {
	Debugf(format, args...)
}
