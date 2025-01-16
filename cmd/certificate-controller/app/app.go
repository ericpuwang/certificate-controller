package app

import (
	"context"
	"fmt"

	"github.com/ericpuwang/certificate-controller/pkg/controller"
	"github.com/ericpuwang/certificate-controller/pkg/options"
	"github.com/spf13/cobra"
	"k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"
)

func NewCertificateControllerCommand(ctx context.Context) *cobra.Command {
	opt, err := options.NewCertificateControllerOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command option: %v", err)
	}

	cmd := &cobra.Command{
		Use:          "certificate-controller",
		Long:         "Customer csr signing controller",
		SilenceUsage: true,
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), arg)
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			verflag.PrintAndExitIfRequested()
			flag.PrintFlags(cmd.Flags())

			if err := opt.Complete(); err != nil {
				klog.Exit(err)
			}
			if err := opt.Validate(); err != nil {
				klog.Exit(err)
			}

			cs, err := controller.NewCertificateController(opt)
			if err != nil {
				klog.Exit(err)
			}
			cs.Run(ctx)
		},
	}

	cmd.SetContext(ctx)

	fs := cmd.Flags()
	namedFlagSets := opt.Flags()
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	flag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)
	return cmd
}
