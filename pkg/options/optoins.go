package options

import (
	"fmt"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/component-base/cli/flag"
)

type CertificateControllerOptions struct {
	SigningCertFile string
	SigningKeyFile  string
	KubeConfig      string
}

func NewCertificateControllerOptions() (*CertificateControllerOptions, error) {
	return &CertificateControllerOptions{}, nil
}

func (o *CertificateControllerOptions) Complete() error {
	return nil
}

func (o *CertificateControllerOptions) Validate() error {
	var allErrs []error
	if len(o.SigningCertFile) == 0 && len(o.SigningKeyFile) == 0 {
		allErrs = append(allErrs, fmt.Errorf("missing filename for serving cert"))
	}
	return utilerrors.NewAggregate(allErrs)
}

func (o *CertificateControllerOptions) Flags() flag.NamedFlagSets {
	fss := flag.NamedFlagSets{}
	pflag := fss.FlagSet("global")

	pflag.StringVar(&o.SigningCertFile, "signing-cert-file", o.SigningCertFile, "Filename containing a PEM-encoded X509 CA certificate used to issue certificates for the cms.io/app-serving")
	pflag.StringVar(&o.SigningKeyFile, "signing-key-file", o.SigningKeyFile, "Filename containing a PEM-encoded RSA or ECDSA private key used to sign certificates for the cms.io/app-serving")
	pflag.StringVar(&o.KubeConfig, "kubeconfig", o.KubeConfig, "path to the kubeconfig file to use for apiserver proxy")

	return fss
}
