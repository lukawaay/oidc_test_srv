package config

import (
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type Client struct {
	ID string
	Secret string
	RedirectURIs []string
	PostLogoutRedirectURIs []string
	ApplicationType op.ApplicationType
	AuthMethod oidc.AuthMethod
	ResponseTypes []oidc.ResponseType
	GrantTypes []oidc.GrantType
}

type Source struct {
	DetailsPath string
	Host string
	Port string
	UserAgentEndpoint string
}

type Details struct {
	Users []oidc.UserInfo
	Clients []Client
}

type Config struct {
	Host string
	Port int
	UserAgentEndpoint string
	Details Details
}

const (
	AuthEndpoint = "/authorize"
	DeviceAuthEndpoint = "/device"
	LogoutEndpoint = "/logged-out"
	LoginEndpoint = "/login"
	LoginSubjectEndpoint  = "/login/subject"
)

func LoginWithID(id string) string {
	return "/login?authRequestID=" + id
}

func Load(source Source) (*Config, error) {
	f, err := os.Open(source.DetailsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var details Details
	if err = json.Unmarshal(bytes, &details); err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(source.Port)
	if err != nil {
		return nil, err
	}

	return &Config {
		Host: source.Host,
		Port: port,
		UserAgentEndpoint: source.UserAgentEndpoint,
		Details: details,
	}, nil
}
