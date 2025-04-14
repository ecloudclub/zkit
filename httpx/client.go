package httpx

import (
	"context"
	"io"
	"net/http"

	"github.com/ecloudclub/zkit/iox"
)

type Request struct {
	req    *http.Request
	err    error
	client *http.Client
}

func NewRequest(ctx context.Context, method string, url string) *Request {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	return &Request{
		req:    req,
		err:    err,
		client: http.DefaultClient,
	}
}

// JSONBody uses JSON as req.Body.
func (r *Request) JSONBody(val any) *Request {
	if r.err != nil {
		return r
	}
	r.req.Body = io.NopCloser(iox.NewJSONReader(val))
	r.req.Header.Set("Content-Type", "application/json")

	return r
}

// Client replaces the default Client with the custom implementation passed in.
func (r *Request) Client(cli *http.Client) *Request {
	r.client = cli
	return r
}

func (r *Request) AddHeader(key string, val string) *Request {
	if r.err != nil {
		return r
	}
	r.req.Header.Add(key, val)
	return r
}

func (r *Request) AddParam(key string, val string) *Request {
	if r.err != nil {
		return r
	}
	qy := r.req.URL.Query()
	qy.Add(key, val)
	r.req.URL.RawQuery = qy.Encode()
	return r
}

func (r *Request) Do() *Response {
	if r.err != nil {
		return &Response{
			err: r.err,
		}
	}
	resp, err := r.client.Do(r.req)
	return &Response{
		Response: resp,
		err:      err,
	}
}
