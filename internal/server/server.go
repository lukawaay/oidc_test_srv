package server

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/lukawaay/oidc_test_srv/internal/server/config"
	"github.com/lukawaay/oidc_test_srv/internal/server/impl"

	"github.com/gin-gonic/gin"
	"github.com/gwatts/gin-adapter"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

type GetLogin struct {
	AuthRequestID string `form:"authRequestID"`
}

type PostLogin struct {
	AuthRequestID string `form:"authRequestID"`
}

//go:embed templates/*
var templateFS embed.FS

func Start(cfg *config.Config, logger *slog.Logger) error {
	r := gin.Default()

	tmpl, err := template.ParseFS(templateFS, "templates/*")
	if err != nil {
		return err
	}
	r.SetHTMLTemplate(tmpl)

	authURL := cfg.UserAgentEndpoint + config.AuthEndpoint
	issuer := fmt.Sprintf("http://%s:%d/", cfg.Host, cfg.Port)

	// Setup oidc implementation:

	storage := impl.CreateStorage(cfg)

	opCfg := &op.Config {
		DefaultLogoutRedirectURI: config.LogoutEndpoint,
		CodeMethodS256: true,
		AuthMethodPost: true,
		AuthMethodPrivateKeyJWT: false,
		GrantTypeRefreshToken: true,
		RequestObjectSupported: true,
		SupportedUILocales: []language.Tag{ language.English },
		DeviceAuthorization: op.DeviceAuthorizationConfig {
			Lifetime: 5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: config.DeviceAuthEndpoint,
			UserCode: op.UserCodeBase20,
		},
	}

	opts := []op.Option {
		op.WithAllowInsecure(),
		op.WithCustomAuthEndpoint(op.NewEndpointWithURL(config.AuthEndpoint, authURL)),
		op.WithLogger(logger.WithGroup("op")),
	}
	provider, err := op.NewOpenIDProvider(issuer, opCfg, storage, opts...)
	if err != nil {
		return err
	}

	// Setup API endpoints:

	loginInterceptor := adapter.Wrap(op.NewIssuerInterceptor(provider.IssuerFromRequest).Handler)
	loginCallbackUrl := op.AuthCallbackURL(provider)

	// Handle errors.
	r.Use(func(c *gin.Context) {
		c.Next()
		err := c.Errors.Last()
		if err == nil {
			return
		}

		logger.Error(fmt.Sprint(err))

		c.HTML(c.Writer.Status(), "error", gin.H {
			"error": err.Error(),
		})
	})


	// Respond to unimplemented device auth endpoint.
	r.Any(config.DeviceAuthEndpoint, func(c *gin.Context) {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Device auth endpoint unimplemented"))
	})

	// Render the login endpoint.
	r.GET(config.LoginEndpoint, func(c *gin.Context) {
		var req GetLogin
		if c.Bind(&req) != nil {
			return
		}

		c.HTML(http.StatusOK, "login", gin.H {
			"authId": req.AuthRequestID,
			"users": cfg.Details.Users,
			"base": config.LoginSubjectEndpoint,
		})
	})

	// Handle login results.
	r.GET(config.LoginSubjectEndpoint + "/:selectedID", loginInterceptor, func(c *gin.Context) {
		var req PostLogin
		if c.Bind(&req) != nil {
			return
		}

		request, err := storage.LocalRequestByID(req.AuthRequestID)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		request.FinishWithSubject(c.Param("selectedID"))
		c.Redirect(http.StatusFound, loginCallbackUrl(c.Request.Context(), req.AuthRequestID))
	})

	// Attach oidc router.
	r.Use(gin.WrapH(http.Handler(provider)))

	// Run!
	return r.Run(fmt.Sprintf(":%d", cfg.Port))
}
