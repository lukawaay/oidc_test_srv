package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/lukawaay/oidc_test_srv/internal/server"
	"github.com/lukawaay/oidc_test_srv/internal/server/config"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(config.Source {
		DetailsPath: os.Getenv("OIDC_TEST_SRV_DETAILS_FILE"),
		Host: os.Getenv("OIDC_TEST_SRV_HOST"),
		Port: os.Getenv("OIDC_TEST_SRV_PORT"),
		UserAgentEndpoint: os.Getenv("OIDC_TEST_SRV_USER_AGENT_ENDPOINT"),
	})

	if err != nil {
		logger.Error(fmt.Sprintf("Failed to load the config: %s", err))
		os.Exit(1)
	}

	if err := server.Start(cfg, logger); err != nil {
		logger.Error(fmt.Sprintf("Failed to start the server: %s", err))

	}
}
