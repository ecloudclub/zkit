package iox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSONReader(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
		val   any

		wantRes []byte
		wantN   int
		wantErr error
	}{
		{
			name:    "normal reading",
			input:   make([]byte, 10),
			wantN:   10,
			val:     User{Name: "Tom"},
			wantRes: []byte(`{"name":"T`),
		},
		{
			name:    "input nil",
			input:   make([]byte, 7),
			wantN:   4,
			wantRes: append([]byte(`null`), 0, 0, 0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := NewJSONReader(tc.val)
			n, err := reader.Read(tc.input)
			assert.Equal(t, tc.wantErr, err)
			assert.Equal(t, tc.wantN, n)
			assert.Equal(t, tc.wantRes, tc.input)
		})
	}
}

type User struct {
	Name string `json:"name"`
}
