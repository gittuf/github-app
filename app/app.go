// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gittuf/github-app/internal/webhook"
	"github.com/kelseyhightower/envconfig"
)

func Execute() {
	/*
		This is heavily inspired by the webhook in
		https://github.com/chainguard-dev/octo-sts written by @wlynch.
	*/

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var env webhook.EnvConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Panicf("unable to process environment variables: %s", err.Error())
	}

	log.Default().Println("Processed env vars")

	mux := http.NewServeMux()
	mux.Handle("/", &webhook.GittufApp{Params: &env})

	log.Default().Println("Serving...")
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", env.Port),
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}
	log.Panic(srv.ListenAndServe())
}
