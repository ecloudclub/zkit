package stringx

import "unsafe"

// UnsafeToBytes Unsafe string to []byte
func UnsafeToBytes(val string) []byte {
	// 1. Convert a string pointer to a pointer to [2]uintptr
	// The representation of a string in memory is a structure containing two fields:
	// - data pointer (uintptr)
	// - length (uintptr)
	sh := (*[2]uintptr)(unsafe.Pointer(&val))

	// 2. Constructing the internal representation of a byte slice
	// The in-memory representation of a byte slice is a structure containing three fields:
	// - data pointer (uintptr) - same as string
	// - length (uintptr) - same as string
	// - capacity (uintptr) - set here to be the same as length
	bh := [3]uintptr{sh[0], sh[1], sh[1]}

	// 3. Convert the constructed byte slice representation to an actual []byte type
	return *(*[]byte)(unsafe.Pointer(&bh))
}

// UnsafeToString Unsafe []byte to string
func UnsafeToString(val []byte) string {
	// 1. Convert the byte slice pointer to a pointer to [3]uintptr
	// The representation of a byte slice in memory is a structure containing three fields:
	// - data pointer (uintptr)
	// - length (uintptr)
	// - capacity (uintptr)
	bh := (*[3]uintptr)(unsafe.Pointer(&val))

	// 2. Constructing the internal representation of a string
	// The string only needs the first two fields (pointer and length), ignoring the capacity field
	sh := [2]uintptr{bh[0], bh[1]}

	// 3. Converting the constructed string representation to an actual string type
	return *(*string)(unsafe.Pointer(&sh))
}
