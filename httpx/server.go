package httpx

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	*http.Response
	err error
}

func (r *Response) JSONReceive(val any) error {
	if r.err != nil {
		return r.err
	}
	err := json.NewDecoder(r.Body).Decode(&val)
	return err
}
