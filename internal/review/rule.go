package review

type Rule interface {
	Name() string
	Check(diff string) []Finding
}