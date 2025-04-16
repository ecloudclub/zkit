package authn

import (
	"context"
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/elastic/pkcs8"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	defaultTokenLookUp      = "header:Authorization"
	defaultSigningAlgorithm = "HS256"
	defaultTimeout          = time.Hour
	defaultTokenHeadName    = "Bearer"
	defaultRealm            = "zkit jwt"

	headerAuthorize = "authorization"
)

var (
	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = errors.New("token is expired") // in practice, this is generated from the jwt library not by us
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = errors.New("secret key is required")
	// ErrEmptyAuthHeader can be thrown if authing with an HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = errors.New("auth header is empty")
	// ErrInvalidAuthHeader indicates auth header is invalid, could, for example, have the wrong Realm name
	ErrInvalidAuthHeader = errors.New("auth header is invalid")
	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = errors.New("query token is empty")
	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = errors.New("cookie token is empty")
	// ErrEmptyParamToken can be thrown if authing with parameter in a path, the parameter in path is empty
	ErrEmptyParamToken = errors.New("parameter token is empty")
	// ErrEmptyFormToken can be thrown if authing with post form, the form token is empty
	ErrEmptyFormToken = errors.New("form token is empty")
	// ErrInvalidSigningAlgorithm indicates the signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = errors.New("invalid signing algorithm")
	// ErrNoPriKeyFile indicates that the given private key is unreadable
	ErrNoPriKeyFile = errors.New("private key file unreadable")
	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = errors.New("public key file unreadable")
	// ErrInvalidPriKey indicates that the given private key is invalid
	ErrInvalidPriKey = errors.New("private key invalid")
	// ErrInvalidPubKey indicates the given public key is invalid
	ErrInvalidPubKey = errors.New("public key invalid")
)

// MapClaims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

type JWTHandler struct {
	config *Config
}

type Config struct {
	// Realm name to display to the user. Required.
	Realm string

	// signing algorithm - possible values are HS256, HS384, HS512, RS256, RS384 or RS512
	// Optional, default is HS256.
	SigningAlgorithm string

	// SecretKey used for signing. Required.
	SecretKey []byte

	// Callback to retrieve key used for signing. Setting KeyFunc will bypass
	// all other key settings
	KeyFunc func(token *jwt.Token) (interface{}, error)

	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration

	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is TokenTime + MaxRefresh.
	// Optional, defaults to 0 meaning not refreshable.
	MaxRefresh time.Duration

	// Callback function that will be called during login.
	// Using this function, it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optionally, by default, no additional data will be set.
	PayloadFunc func(data interface{}) MapClaims

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	// - "param:<name>"
	// - "form:<name>"
	TokenLookup string

	// TokenHeadName is a string in the header. The Default value is "Bearer"
	TokenHeadName string

	// Private key file for asymmetric algorithms
	PriKeyFile string
	// Private Key bytes for asymmetric algorithms
	//
	// Note: PriKeyFile takes precedence over PriKeyBytes if both are set
	PriKeyBytes []byte

	// Private key passphrase
	PrivateKeyPassphrase string

	// Public key file for asymmetric algorithms
	PubKeyFile string

	// Public key bytes for asymmetric algorithms.
	//
	// Note: PubKeyFile takes precedence over PubKeyBytes if both are set
	PubKeyBytes []byte

	// Private key
	priKey *rsa.PrivateKey

	// Public key
	pubKey *rsa.PublicKey

	// ParseOptions allow modifying jwt's parser methods
	ParseOptions []jwt.ParserOption
}

func New(cfg *Config) (*JWTHandler, error) {
	mw := &JWTHandler{config: cfg}

	if err := mw.InitConfig(); err != nil {
		return nil, err
	}

	return mw, nil
}

func (h *JWTHandler) InitConfig() error {
	if h.config.TokenLookup == "" {
		h.config.TokenLookup = defaultTokenLookUp
	}

	if h.config.SigningAlgorithm == "" {
		h.config.SigningAlgorithm = defaultSigningAlgorithm
	}

	if h.config.Timeout == 0 {
		h.config.Timeout = defaultTimeout
	}

	h.config.TokenHeadName = strings.TrimSpace(h.config.TokenHeadName)
	if h.config.TokenHeadName == "" {
		h.config.TokenHeadName = defaultTokenHeadName
	}

	if h.config.Realm == "" {
		h.config.Realm = defaultRealm
	}

	if h.config.KeyFunc != nil {
		// bypass other key settings if KeyFunc is set
		return nil
	}

	if h.usingPublicKeyAlgo() {
		return h.readKeys()
	}

	if h.config.SecretKey == nil {
		return ErrMissingSecretKey
	}

	return nil
}

func (h *JWTHandler) GenerateToken(data any) (string, error) {
	claims := jwt.MapClaims{}
	if h.config.PayloadFunc != nil {
		for key, value := range h.config.PayloadFunc(data) {
			claims[key] = value
		}
	}
	expire := time.Now().UTC().Add(h.config.Timeout)
	claims["expire"] = expire.Unix()
	claims["orig_iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.GetSigningMethod(h.config.SigningAlgorithm), claims)
	tokenStr, err := h.signedString(token)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (h *JWTHandler) signedString(token *jwt.Token) (string, error) {
	var tokenStr string
	var err error
	if h.usingPublicKeyAlgo() {
		tokenStr, err = token.SignedString(h.config.priKey)
	} else {
		tokenStr, err = token.SignedString(h.config.SecretKey)
	}

	return tokenStr, err
}

func (h *JWTHandler) ParseToken(ctx context.Context) (*jwt.Token, error) {
	var token string
	var err error
	switch c := ctx.(type) {
	case *gin.Context:
		token, err = h.getGinToken(c)
	default:
		token, err = h.getGRPCToken(c, "Bearer")
	}
	if err != nil {
		return nil, err
	}

	if h.config.KeyFunc != nil {
		return jwt.Parse(token, h.config.KeyFunc, h.config.ParseOptions...)
	}

	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(h.config.SigningAlgorithm) != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if h.usingPublicKeyAlgo() {
			return h.config.pubKey, nil
		}

		return h.config.SecretKey, nil
	}, h.config.ParseOptions...)
}

func (h *JWTHandler) CheckExpire(ctx context.Context) (jwt.MapClaims, error) {
	token, err := h.ParseToken(ctx)
	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < time.Now().Add(-h.config.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

func (h *JWTHandler) RefreshToken(ctx context.Context) (string, error) {
	claims, err := h.CheckExpire(ctx)
	if err != nil {
		return "", err
	}

	// create new token
	newClaims := make(jwt.MapClaims, len(claims))
	for k, v := range claims {
		newClaims[k] = v
	}
	expire := time.Now().UTC().Add(h.config.Timeout)
	newClaims["expire"] = expire.Unix()
	newClaims["orig_iat"] = time.Now().Unix()
	newToken := jwt.NewWithClaims(jwt.GetSigningMethod(h.config.SigningAlgorithm), newClaims)
	tokenStr, err := h.signedString(newToken)

	return tokenStr, err
}

func (h *JWTHandler) getGinToken(c *gin.Context) (string, error) {
	var token string
	var err error

	parts := strings.Split(strings.TrimSpace(h.config.TokenLookup), ":")
	k := strings.TrimSpace(parts[0])
	v := strings.TrimSpace(parts[1])

	switch k {
	case "header":
		token, err = h.jwtFromHeader(c, v)
	case "cookie":
		token, err = h.jwtFromCookie(c, v)
	case "query":
		token, err = h.jwtFromQuery(c, v)
	case "param":
		token, err = h.jwtFromParam(c, v)
	case "form":
		token, err = h.jwtFromForm(c, v)
	}

	return token, err
}

func (h *JWTHandler) getGRPCToken(ctx context.Context, expectedScheme string) (string, error) {
	vals := metadata.ValueFromIncomingContext(ctx, headerAuthorize)
	if len(vals) == 0 {
		return "", status.Error(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
	}
	scheme, token, found := strings.Cut(vals[0], " ")
	if !found {
		return "", status.Error(codes.Unauthenticated, "Bad authorization string")
	}
	if !strings.EqualFold(scheme, expectedScheme) {
		return "", status.Error(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
	}
	return token, nil
}

func (h *JWTHandler) readKeys() error {
	err := h.privateKey()
	if err != nil {
		return err
	}
	err = h.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (h *JWTHandler) privateKey() error {
	var keyData []byte
	if h.config.PriKeyFile == "" {
		keyData = h.config.PriKeyBytes
	} else {
		content, err := os.ReadFile(h.config.PriKeyFile)
		if err != nil {
			return ErrNoPriKeyFile
		}
		keyData = content
	}

	if h.config.PrivateKeyPassphrase != "" {
		key, err := pkcs8.ParsePKCS8PrivateKey(keyData, []byte(h.config.PrivateKeyPassphrase))
		if err != nil {
			return ErrInvalidPriKey
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPriKey
		}

		h.config.priKey = rsaKey
		return nil
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPriKey
	}
	h.config.priKey = key
	return nil
}

func (h *JWTHandler) publicKey() error {
	var keyData []byte
	if h.config.PubKeyFile == "" {
		keyData = h.config.PubKeyBytes
	} else {
		content, err := os.ReadFile(h.config.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = content
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	h.config.pubKey = key
	return nil
}

func (h *JWTHandler) usingPublicKeyAlgo() bool {
	switch h.config.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

func (h *JWTHandler) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == h.config.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[len(parts)-1], nil
}

func (h *JWTHandler) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (h *JWTHandler) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, err := c.Cookie(key)
	if err != nil {
		return "", err
	}

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (h *JWTHandler) jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (h *JWTHandler) jwtFromForm(c *gin.Context, key string) (string, error) {
	token := c.PostForm(key)

	if token == "" {
		return "", ErrEmptyFormToken
	}

	return token, nil
}
