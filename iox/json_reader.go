package iox

import (
	"bytes"

	"github.com/bytedance/sonic"
)

type JSONReader struct {
	val any
	buf *bytes.Reader
}

// NewJSONReader is used to solve the scenario of serializing a structure into JSON and then wrapping it into io.Reader.
//
// Currently, the implementation does not have any checks;
// you need to make sure that the incoming object can be serialized in JSON.
//
// Also, non-thread-safe. If you pass in nil, then the read is also nil.
func NewJSONReader(val any) *JSONReader {
	return &JSONReader{
		val: val,
	}
}

func (r *JSONReader) Read(obj []byte) (n int, err error) {
	if r.buf == nil {
		var data []byte
		data, err = sonic.Marshal(r.val)
		if err == nil {
			r.buf = bytes.NewReader(data)
		}
	}
	if err != nil {
		return
	}

	return r.buf.Read(obj)
}
