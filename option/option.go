package option

// Option is a generic design for the Option pattern.
// Avoid defining a lot of structures like this in your code
// In general, T should be a structure.
type Option[T any] func(t *T)

// Apply applies opts to t.
func Apply[T any](t *T, opts ...Option[T]) {
	for _, opt := range opts {
		opt(t)
	}
}
