package review

type Finding struct {
	Rule     string
	Severity string
	File     string
	Line     int
	Message  string
}