package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ecloudclub/zkit/auth/authn"
)

type User struct {
	Id   int
	Name string
}

func main() {
	cfg := &authn.Config{
		SecretKey: []byte("gE1cK7kD1pK5aV9jT6fA6nV4dQ7zO1cT"),
		Timeout:   600,
		PayloadFunc: func(data interface{}) authn.MapClaims {
			if v, ok := data.(*User); ok {
				return authn.MapClaims{
					"id":   v.Id,
					"name": v.Name,
				}
			}
			return authn.MapClaims{}
		},
		TokenLookup:   "header:Authorization",
		TokenHeadName: "Bearer",
	}
	handler, err := authn.New(cfg)
	if err != nil {
		panic(err)
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

	go func() {
		if err := server.Run("localhost:8082"); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	token, err := handler.GenerateToken(&User{Id: 1, Name: "frank"})
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://localhost:8082/hello", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := http.DefaultClient

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}
