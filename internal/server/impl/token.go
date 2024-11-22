package impl 

import (
	"time"
)

type AccessToken struct {
	id string
	appID string
	refreshTokenID string
	subject string
	audience []string
	scopes []string
	expiration time.Time
}

type RefreshToken struct {
	id string
	access *AccessToken
	authTime time.Time
	amr []string
	scopes []string
	expiration time.Time
}

func newAccessToken(id, appID, refreshTokenID, subject string, audience, scopes []string) *AccessToken {
	return &AccessToken {
		id: id,
		appID: appID,
		refreshTokenID: refreshTokenID,
		subject: subject,
		audience: audience,
		scopes: scopes,
		expiration: time.Now().Add(5 * time.Minute),
	}
}

func newRefreshToken(id string, accessToken *AccessToken, amr []string, authTime time.Time) *RefreshToken {
	return &RefreshToken {
		id: id,
		access: accessToken,
		authTime: authTime,
		amr: amr,
		expiration: time.Now().Add(5 * time.Hour),
		scopes: accessToken.scopes,
	}
}

func (r *RefreshToken) GetAMR() []string {
	return r.amr
}

func (r *RefreshToken) GetAudience() []string {
	return r.access.audience
}

func (r *RefreshToken) GetAuthTime() time.Time {
	return r.authTime
}

func (r *RefreshToken) GetClientID() string {
	return r.access.appID
}

func (r *RefreshToken) GetScopes() []string {
	return r.access.scopes
}

func (r *RefreshToken) GetSubject() string {
	return r.access.subject
}

func (r *RefreshToken) SetCurrentScopes(scopes []string) {
	r.scopes = scopes
}
