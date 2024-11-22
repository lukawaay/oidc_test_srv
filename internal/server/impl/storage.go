package impl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/lukawaay/oidc_test_srv/internal/server/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Storage struct {
	config *config.Config
	auth map[string]*AuthRequest
	accessTokens map[string]*AccessToken
	refreshTokens map[string]*RefreshToken
	clients map[string]*Client
	signingKey *SigningKey
	signatureAlgorithms []jose.SignatureAlgorithm
}

func CreateStorage(cfg *config.Config) *Storage {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	clients := map[string]*Client{}

	for _, client := range cfg.Details.Clients {
		clients[client.ID] = &Client { cfg: client }
	}

	return &Storage {
		config: cfg,
		auth: map[string]*AuthRequest{},
		accessTokens: map[string]*AccessToken{},
		refreshTokens: map[string]*RefreshToken{},
		clients: clients,
		signingKey: &SigningKey {
			id: uuid.NewString(),
			algorithm: jose.RS256,
			key: key,
		},
		signatureAlgorithms: []jose.SignatureAlgorithm { jose.RS256 },
	}
}

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	internal := newAuthRequest(req, userID)
	s.auth[internal.id] = internal

	return internal, nil
}

func (s *Storage) LocalRequestByID(id string) (*AuthRequest, error) {
	res, ok := s.auth[id]
	if !ok {
		return nil, fmt.Errorf("request not found")
	}

	return res, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	return s.LocalRequestByID(id)
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	for _, auth := range s.auth {
		if auth.code != "" && auth.code == code {
			return auth, nil
		}
	}

	return nil, fmt.Errorf("request not found")
}

func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	auth, err := s.LocalRequestByID(id)
	if err != nil {
		return err
	}

	auth.code = code

	return nil
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	_, ok := s.auth[id]
	if !ok {
		return fmt.Errorf("request not found")
	}

	delete(s.auth, id)

	return nil
}

func (s *Storage) CreateAccessToken(ctx context.Context, data op.TokenRequest) (accessTokenID string, expiration time.Time, err error) {
	var appID string

	switch req := data.(type) {
	case *AuthRequest:
		appID = req.appID
	case op.TokenExchangeRequest:
		appID = req.GetClientID()
	}
	token := newAccessToken(uuid.NewString(), appID, "", data.GetSubject(), data.GetAudience(), data.GetScopes())
	s.accessTokens[token.id] = token

	return token.id, token.expiration, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, data op.TokenRequest, oldRefreshTokenId string) (newAccessTokenID string, newRefreshTokenID string, expiration time.Time, err error) {
	// Collect information about  the new tokens:

	var authTime time.Time
	var appID string
	var amr []string
	subject := data.GetSubject()
	audience := data.GetAudience()
	scopes := data.GetScopes()

	switch req := data.(type) {
	case *RefreshToken:
		appID = req.access.appID
		authTime = req.authTime
		amr = req.GetAMR()
	case *AuthRequest:
		appID = req.appID
		authTime = req.GetAuthTime()
		amr = req.GetAMR()
	default:
		err = fmt.Errorf("Unimplemented")
		return
	}

	// If using a refresh token, make sure it exists and delete it alongside
	// its old token.
	if oldRefreshTokenId != "" {
		oldRefreshToken, ok := s.refreshTokens[oldRefreshTokenId]
		if !ok {
			err = fmt.Errorf("invalid refresh token")
			return
		}

		delete(s.accessTokens, oldRefreshToken.access.id)
		delete(s.refreshTokens, oldRefreshTokenId)
	}

	// Create the new tokens:

	newRefreshTokenID = uuid.NewString()

	accessToken := newAccessToken(uuid.NewString(), appID, newRefreshTokenID, subject, audience, scopes)
	s.accessTokens[accessToken.id] = accessToken

	refreshToken := newRefreshToken(newRefreshTokenID, accessToken, amr, authTime)
	s.refreshTokens[refreshToken.id] = refreshToken

	newAccessTokenID = accessToken.id
	expiration = accessToken.expiration
	
	return
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	res, ok := s.refreshTokens[refreshTokenID]
	if !ok {
		return nil, fmt.Errorf("refresh token not found")
	}

	return res, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	for _, token := range s.accessTokens {
		if token.appID == clientID && token.subject == userID {
			delete(s.accessTokens, token.id)
			delete(s.refreshTokens, token.refreshTokenID)
		}
	}

	return nil
}

func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	accessToken, isAccessToken := s.accessTokens[tokenOrTokenID]
	refreshToken, isRefreshToken := s.refreshTokens[tokenOrTokenID]

	if isAccessToken {
		delete(s.accessTokens, accessToken.id)
		delete(s.refreshTokens, accessToken.refreshTokenID)
	} else if isRefreshToken {
		delete(s.accessTokens, refreshToken.access.id)
		delete(s.refreshTokens, refreshToken.id)
	} else {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}

	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	refreshToken, ok := s.refreshTokens[token]
	if !ok || refreshToken.access.subject != clientID {
		err = op.ErrInvalidRefreshToken
		return
	}

	userID = refreshToken.access.subject
	tokenID = refreshToken.id
	return
}

func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) {
	return s.signingKey, nil
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return s.signatureAlgorithms, nil
}

func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{ newKey(s.signingKey) }, nil
}

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	res, ok := s.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}

	return res, nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found")
	}

	if client.cfg.Secret != clientSecret {
		return fmt.Errorf("invalid client secret")
	}

	return nil
}

// Depreciated
func (s *Storage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return nil;
}

func (s *Storage) setUserInfo(ctx context.Context, userinfo *oidc.UserInfo, subject string, clientID string, scopes []string) error {
	for _, user := range s.config.Details.Users {
		if user.Subject == subject {
			*userinfo = user
			return nil
		}
	}

	return fmt.Errorf("subject not found")
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	return s.setUserInfo(ctx, userinfo, request.GetSubject(), request.GetClientID(), scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	token, ok := s.accessTokens[tokenID]
	if !ok {
		return fmt.Errorf("invalid token")
	}

	return s.setUserInfo(ctx, userinfo, token.subject, token.appID, token.scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	token, ok := s.accessTokens[tokenID]
	if !ok {
		return fmt.Errorf("invalid token")
	}

	hasAudience := false
	for _, aud := range token.audience {
		if aud == clientID {
			hasAudience = true
			break
		}
	}
	if !hasAudience {
		return fmt.Errorf("invalid token")
	}

	userInfo := oidc.UserInfo{}
	err := s.setUserInfo(ctx, &userInfo, subject, clientID, token.scopes)
	if err != nil {
		return err
	}

	introspection.SetUserInfo(&userInfo)
	introspection.Scope = token.scopes
	introspection.ClientID = token.appID

	return nil
}

func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	for _, user := range s.config.Details.Users {
		if user.Subject == userID {
			return user.Claims, nil
		}
	}

	return nil, fmt.Errorf("subject not found")
}

func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (s *Storage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return nil, fmt.Errorf("Unimplemented")
}

func (s *Storage) Health(context.Context) error {
	return nil
}
