package ptr

// Of returns a pointer to the passed-in object
func Of[T any](value T) *T {
	return &value
}
