package main

import (
	"os"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/DataDog/datadog-agent/comp/logs/agent"
	"github.com/DataDog/datadog-agent/comp/util/log"
)

func main() {
	app := fx.New(
		log.FxOption,
		agent.FxOption,

		// Invoke just has to require the top-level components
		fx.Invoke(func(agent.Component) {}),

		// This will probably be global to all binaries, so maybe cmd.FxOption?
		fx.WithLogger(
			func() fxevent.Logger {
				// (we'd probably want to hook this into agent logging at trace level)
				return &fxevent.ConsoleLogger{W: os.Stderr}
			},
		),
	)
	app.Run()
}
