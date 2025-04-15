package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/ecloudclub/zkit/auth/authn/proto/hello"
)

type User struct {
	Id   int
	Name string
}

func (h *JWTHandler) SetTokenLookup(lookup string) {
	h.config.TokenLookup = lookup
}

func TestGINJWT_MultipleLocations(t *testing.T) {
	// 公共配置
	cfg := &Config{
		SecretKey: []byte("gE1cK7kD1pK5aV9jT6fA6nV4dQ7zO1cT"),
		PayloadFunc: func(data interface{}) MapClaims {
			if v, ok := data.(*User); ok {
				return MapClaims{
					"id":   v.Id,
					"name": v.Name,
				}
			}
			return MapClaims{}
		},
	}

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create JWT handler: %v", err)
	}

	server := gin.Default()
	server.GET("/hello", func(c *gin.Context) {
		token, err := handler.ParseToken(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}
		c.JSON(http.StatusOK, token)
	})

	server.GET("/hello/:token", func(c *gin.Context) {
		token, err := handler.ParseToken(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}
		c.JSON(http.StatusOK, token)
	})

	server.POST("/hello", func(c *gin.Context) {
		token, err := handler.ParseToken(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}
		c.JSON(http.StatusOK, token)
	})

	go func() {
		if err := server.Run("localhost:8082"); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	token, err := handler.GenerateToken(&User{Id: 1, Name: "frank"})
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	testCases := []struct {
		name        string
		tokenLookup string
		setupReq    func(*http.Request)
		url         string
		method      string
		description string
	}{
		{
			name:        "HeaderAuth",
			tokenLookup: "header:Authorization",
			setupReq:    func(req *http.Request) { req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token)) },
			url:         "http://localhost:8082/hello",
			method:      http.MethodGet,
			description: "Test JWT passed through Authorization header",
		},
		{
			name:        "CookieAuth",
			tokenLookup: "cookie:refresh_token",
			setupReq:    func(req *http.Request) { req.AddCookie(&http.Cookie{Name: "refresh_token", Value: token}) },
			url:         "http://localhost:8082/hello",
			method:      http.MethodGet,
			description: "Testing JWT Delivery via Cookie",
		},
		{
			name:        "QueryAuth",
			tokenLookup: "query:token",
			setupReq:    func(req *http.Request) {},
			url:         fmt.Sprintf("http://localhost:8082/hello?token=%s", url.QueryEscape(token)),
			method:      http.MethodGet,
			description: "Testing JWT Passing via Query Parameters",
		},
		{
			name:        "ParamAuth",
			tokenLookup: "param:token",
			setupReq:    func(req *http.Request) {},
			url:         fmt.Sprintf("http://localhost:8082/hello/%s", url.PathEscape(token)),
			method:      http.MethodGet,
			description: "Testing JWT Passing via URL Parameters",
		},
		{
			name:        "FormAuth",
			tokenLookup: "form:token",
			setupReq: func(req *http.Request) {
				body := strings.NewReader(fmt.Sprintf("token=%s", url.QueryEscape(token)))
				req.Body = io.NopCloser(body)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			},
			url:         "http://localhost:8082/hello",
			method:      http.MethodPost,
			description: "Testing JWT Passing through Form Forms",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Log(tc.description)

			// Dynamically set the TokenLookup
			handler.SetTokenLookup(tc.tokenLookup)

			req, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			tc.setupReq(req)

			client := http.DefaultClient
			res, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(res.Body)
				t.Errorf("Expected status 200, got %d, body: %s", res.StatusCode, string(body))
			} else {
				var result map[string]interface{}
				if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				t.Logf("Success with response: %+v", result)
			}
		})
	}
}

func TestGRPCJWT(t *testing.T) {
	cfg := &Config{
		SecretKey: []byte("gE1cK7kD1pK5aV9jT6fA6nV4dQ7zO1cT"),
		PayloadFunc: func(data interface{}) MapClaims {
			if v, ok := data.(*User); ok {
				return MapClaims{
					"id":   v.Id,
					"name": v.Name,
				}
			}
			return MapClaims{}
		},
	}

	handler, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create JWT handler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startServer(ctx, handler)

	if err := waitForServerReady(":8083", 5*time.Second); err != nil {
		t.Fatal(err)
	}

	t.Run("client test", func(t *testing.T) {
		token, err := handler.GenerateToken(&User{Id: 1, Name: "frank"})
		if err != nil {
			t.Fatal(err)
		}

		md := metadata.Pairs("authorization", "Bearer "+token)
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		res, err := hello.NewHelloServiceClient(getClientConn()).Hello(ctx, &hello.HelloRequest{Msg: "Hello World"})
		if err != nil {
			t.Fatal(err)
		}
		t.Log(res)
	})
}

func startServer(ctx context.Context, h *JWTHandler) {
	server := grpc.NewServer()
	hello.RegisterHelloServiceServer(server, &HelloServer{handler: h})

	lis, err := net.Listen("tcp", ":8083")
	if err != nil {
		panic(err)
	}

	go func() {
		<-ctx.Done()
		server.GracefulStop() // 收到终止信号后优雅关闭
	}()

	if err := server.Serve(lis); err != nil {
		log.Printf("Server exited: %v", err)
	}
}

type HelloServer struct {
	hello.UnimplementedHelloServiceServer
	handler *JWTHandler
}

func (s *HelloServer) Hello(ctx context.Context, req *hello.HelloRequest) (*hello.HelloResponse, error) {
	token, err := s.handler.ParseToken(ctx)
	if err != nil {
		return nil, err
	}
	fmt.Println(token)
	return &hello.HelloResponse{Msg: req.GetMsg()}, nil
}

func getClientConn() grpc.ClientConnInterface {
	cc, err := grpc.NewClient(":8083", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}

	return cc
}

func waitForServerReady(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("server not ready in %v", timeout)
}
