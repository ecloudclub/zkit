package authn

import (
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/elastic/pkcs8"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultTokenLookUp      = "header:Authorization"
	defaultSigningAlgorithm = "HS256"
	defaultTimeout          = time.Hour
	defaultTokenHeadName    = "Bearer"
	defaultRealm            = "zkit jwt"
)

var (
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

type JWTMiddleware struct {
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

func New(cfg *Config) (*JWTMiddleware, error) {
	mw := &JWTMiddleware{config: cfg}

	if err := mw.InitConfig(); err != nil {
		return nil, err
	}

	return mw, nil
}

func (m *JWTMiddleware) InitConfig() error {
	if m.config.TokenLookup == "" {
		m.config.TokenLookup = defaultTokenLookUp
	}

	if m.config.SigningAlgorithm == "" {
		m.config.SigningAlgorithm = defaultSigningAlgorithm
	}

	if m.config.Timeout == 0 {
		m.config.Timeout = defaultTimeout
	}

	m.config.TokenHeadName = strings.TrimSpace(m.config.TokenHeadName)
	if m.config.TokenHeadName == "" {
		m.config.TokenHeadName = defaultTokenHeadName
	}

	if m.config.Realm == "" {
		m.config.Realm = defaultRealm
	}

	if m.config.KeyFunc != nil {
		// bypass other key settings if KeyFunc is set
		return nil
	}

	if m.usingPublicKeyAlgo() {
		return m.readKeys()
	}

	if m.config.SecretKey == nil {
		return ErrMissingSecretKey
	}

	return nil
}

func (m *JWTMiddleware) GenerateToken(data any) (string, error) {
	claims := jwt.MapClaims{}
	if m.config.PayloadFunc != nil {
		for key, value := range m.config.PayloadFunc(data) {
			claims[key] = value
		}
	}
	expire := time.Now().UTC().Add(m.config.Timeout)
	claims["expire"] = expire.Unix()
	claims["orig_iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.GetSigningMethod(m.config.SigningAlgorithm), claims)
	tokenStr, err := m.signedString(token)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (m *JWTMiddleware) signedString(token *jwt.Token) (string, error) {
	var tokenStr string
	var err error
	if m.usingPublicKeyAlgo() {
		tokenStr, err = token.SignedString(m.config.priKey)
	} else {
		tokenStr, err = token.SignedString(m.config.SecretKey)
	}

	return tokenStr, err
}

func (m *JWTMiddleware) ParseToken(c *gin.Context) (*jwt.Token, error) {
	var token string
	var err error

	parts := strings.Split(strings.TrimSpace(m.config.TokenLookup), ":")
	k := strings.TrimSpace(parts[0])
	v := strings.TrimSpace(parts[1])

	switch k {
	case "header":
		token, err = m.jwtFromHeader(c, v)
	case "cookie":
		token, err = m.jwtFromCookie(c, v)
	case "query":
		token, err = m.jwtFromQuery(c, v)
	case "param":
		token, err = m.jwtFromParam(c, v)
	case "form":
		token, err = m.jwtFromForm(c, v)
	}
	if err != nil {
		return nil, err
	}

	if m.config.KeyFunc != nil {
		return jwt.Parse(token, m.config.KeyFunc, m.config.ParseOptions...)
	}

	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(m.config.SigningAlgorithm) != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if m.usingPublicKeyAlgo() {
			return m.config.pubKey, nil
		}

		// save token string if valid
		c.Set("JWT_TOKEN", token)

		return m.config.SecretKey, nil
	}, m.config.ParseOptions...)
}

func (m *JWTMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == m.config.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[len(parts)-1], nil
}

func (m *JWTMiddleware) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (m *JWTMiddleware) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, err := c.Cookie(key)
	if err != nil {
		return "", err
	}

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (m *JWTMiddleware) jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (m *JWTMiddleware) jwtFromForm(c *gin.Context, key string) (string, error) {
	token := c.PostForm(key)

	if token == "" {
		return "", ErrEmptyFormToken
	}

	return token, nil
}

func (m *JWTMiddleware) readKeys() error {
	err := m.privateKey()
	if err != nil {
		return err
	}
	err = m.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (m *JWTMiddleware) privateKey() error {
	var keyData []byte
	if m.config.PriKeyFile == "" {
		keyData = m.config.PriKeyBytes
	} else {
		content, err := os.ReadFile(m.config.PriKeyFile)
		if err != nil {
			return ErrNoPriKeyFile
		}
		keyData = content
	}

	if m.config.PrivateKeyPassphrase != "" {
		key, err := pkcs8.ParsePKCS8PrivateKey(keyData, []byte(m.config.PrivateKeyPassphrase))
		if err != nil {
			return ErrInvalidPriKey
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidPriKey
		}

		m.config.priKey = rsaKey
		return nil
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPriKey
	}
	m.config.priKey = key
	return nil
}

func (m *JWTMiddleware) publicKey() error {
	var keyData []byte
	if m.config.PubKeyFile == "" {
		keyData = m.config.PubKeyBytes
	} else {
		content, err := os.ReadFile(m.config.PubKeyFile)
		if err != nil {
			return ErrNoPubKeyFile
		}
		keyData = content
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	m.config.pubKey = key
	return nil
}

func (m *JWTMiddleware) usingPublicKeyAlgo() bool {
	switch m.config.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}
