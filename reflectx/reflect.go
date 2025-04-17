package reflectx

import "reflect"

// IsNilValue further encapsulates the IsNil method.
// The IsNil method can be executed if val is of a type map, chan, slice, interface, ptr, and func.
// Otherwise, return false to avoid a panic when the IsNil method is executed.
// In particular, if val itself is an illegal value (e.g., nil), you need to pass the IsValid method first to avoid a later panic.
func IsNilValue(val reflect.Value) bool {
	// Determine if reflect.Value itself is an illegal value, e.g., nil, to avoid a subsequent panic when fetching val.Type().
	if !val.IsValid() {
		return true
	}
	// Determine if the IsNil method can be executed based on the type.
	switch val.Type().Kind() {
	case reflect.Map, reflect.Chan, reflect.Slice, reflect.Interface, reflect.Ptr, reflect.Func, reflect.UnsafePointer:
		return val.IsNil()
	default:
		panic("unhandled default case")
	}
	return false
}
