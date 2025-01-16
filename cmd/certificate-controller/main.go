package main

import (
	"os"

	"github.com/ericpuwang/certificate-controller/cmd/certificate-controller/app"
	"github.com/ericpuwang/certificate-controller/pkg/utils"
	"k8s.io/component-base/cli"
)

func main() {
	ctx := utils.GracefulStopWithContext()
	command := app.NewCertificateControllerCommand(ctx)
	code := cli.Run(command)
	os.Exit(code)
}
