//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package app

import (
	"bytes"
	"fmt"
	"os"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/api/util"
	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/flare"
	"github.com/DataDog/datadog-agent/pkg/util/input"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	customerEmail string
	autoconfirm   bool
	forceLocal    bool
)

func init() {
	SysprobeCmd.AddCommand(flareCmd)

	flareCmd.Flags().StringVarP(&customerEmail, "email", "e", "", "Your email")
	flareCmd.Flags().BoolVarP(&autoconfirm, "send", "s", false, "Automatically send flare (don't prompt for confirmation)")
	flareCmd.Flags().BoolVarP(&forceLocal, "local", "l", false, "Force the creation of the flare by the command line instead of the agent process (useful when running in a containerized env)")
	flareCmd.SetArgs([]string{"caseID"})
}

var (
	flareCmd = &cobra.Command{
		Use:   "flare [caseID]",
		Short: "Collect a flare and send it to Datadog",
		Long:  ``,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagNoColor {
				color.NoColor = true
			}

			cfg, err := config.New(configPath)
			if err != nil {
				return fmt.Errorf("unable to set up system-probe configuration: %v", err)
			}

			// The flare command should not log anything, all errors should be reported directly to the console without the log format
			err = ddconfig.SetupLogger(loggerName, "off", "", "", false, true, false)
			if err != nil {
				fmt.Printf("Cannot setup logger, exiting: %v\n", err)
				return err
			}

			caseID := ""
			if len(args) > 0 {
				caseID = args[0]
			}

			if customerEmail == "" {
				var err error
				customerEmail, err = input.AskForEmail()
				if err != nil {
					fmt.Println("Error reading email, please retry or contact support")
					return err
				}
			}

			return makeFlare(cfg, caseID)
		},
	}
)

func makeFlare(cfg *config.Config, caseID string) error {
	var filePath string
	var err error
	if forceLocal {
		filePath, err = createArchive(cfg, nil)
	} else {
		filePath, err = requestArchive(cfg, caseID)
	}
	if err != nil {
		return err
	}

	if _, err := os.Stat(filePath); err != nil {
		fmt.Fprintln(color.Output, color.RedString(fmt.Sprintf("The flare zipfile \"%s\" does not exist.", filePath)))
		fmt.Fprintln(color.Output, color.RedString("If the system-probe is running in a different container try the '--local' option to generate the flare locally"))
		return err
	}

	fmt.Fprintln(color.Output, fmt.Sprintf("%s is going to be uploaded to Datadog", color.YellowString(filePath)))
	if !autoconfirm {
		confirmation := input.AskForConfirmation("Are you sure you want to upload a flare? [y/N]")
		if !confirmation {
			fmt.Fprintln(color.Output, fmt.Sprintf("Aborting. (You can still use %s)", color.YellowString(filePath)))
			return nil
		}
	}

	response, e := flare.SendFlare(filePath, caseID, customerEmail)
	fmt.Println(response)
	if e != nil {
		return e
	}
	return nil
}

func createArchive(cfg *config.Config, ipcError error) (string, error) {
	fmt.Fprintln(color.Output, color.YellowString("Initiating flare locally."))
	filePath, err := flare.CreateSystemProbeArchive(true, cfg.LogFile, ipcError)
	if err != nil {
		fmt.Printf("The flare zipfile failed to be created: %s\n", err)
		return "", err
	}
	return filePath, nil
}

func requestArchive(cfg *config.Config, caseID string) (string, error) {
	fmt.Fprintln(color.Output, color.BlueString("Asking the systen-probe to build the flare archive."))
	c := api.GetClient(cfg.SocketAddress)
	r, e := util.DoPost(c, "http://localhost/agent/flare", "application/json", bytes.NewBuffer([]byte{}))
	if e != nil {
		if r != nil && string(r) != "" {
			fmt.Fprintln(color.Output, fmt.Sprintf("The system-probe ran into an error while making the flare: %s", color.RedString(string(r))))
			e = fmt.Errorf("error getting flare from running system-probe: %s", r)
		} else {
			fmt.Fprintln(color.Output, color.RedString("The agent was unable to make the flare. (is it running?)"))
			e = fmt.Errorf("error getting flare from running system-probe: %w", e)
		}
		return createArchive(cfg, e)
	}
	return string(r), nil
}
