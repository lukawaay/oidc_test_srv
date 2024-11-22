package impl

import (
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthRequest struct {
	id string
	appID string
	callbackURI string
	transferState string
	prompt []string
	userID string
	scopes []string
	responseType oidc.ResponseType
	responseMode oidc.ResponseMode
	nonce string
	codeChallenge *oidc.CodeChallenge
	authTime time.Time

	code string
	done bool
}

func newAuthRequest(from *oidc.AuthRequest, userID string) *AuthRequest {
	res := AuthRequest {
		id: uuid.NewString(),
		appID: from.ClientID,
		callbackURI: from.RedirectURI,
		transferState: from.State,
		userID: userID,
		scopes: from.Scopes,
		responseType: from.ResponseType,
		responseMode: from.ResponseMode,
		nonce: from.Nonce,
		codeChallenge: &oidc.CodeChallenge {
			Challenge: from.CodeChallenge,
			Method: from.CodeChallengeMethod,
		},
		authTime: time.Now(),
		done: false,
	}

	return &res
}

func (a *AuthRequest) FinishWithSubject(id string) {
	a.done = true
	a.userID = id
}

func (a *AuthRequest) GetID() string {
	return a.id
}

func (a *AuthRequest) GetACR() string {
	return ""
}

func (a *AuthRequest) GetAMR() []string {
	return []string{}
}

func (a *AuthRequest) GetAudience() []string {
	return []string { a.appID }
}

func (a *AuthRequest) GetAuthTime() time.Time {
	return a.authTime
}

func (a *AuthRequest) GetClientID() string {
	return a.appID
}

func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return a.codeChallenge
}

func (a *AuthRequest) GetNonce() string {
	return a.nonce
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.callbackURI
}

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return a.responseType
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return a.responseMode
}

func (a *AuthRequest) GetScopes() []string {
	return a.scopes
}

func (a *AuthRequest) GetState() string {
	return a.transferState
}

func (a *AuthRequest) GetSubject() string {
	return a.userID
}

func (a *AuthRequest) Done() bool {
	return a.done
}
