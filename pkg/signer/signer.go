package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ericpuwang/certificate-controller/pkg/options"
	capi "k8s.io/api/certificates/v1"
	_ "k8s.io/apimachinery"
	_ "k8s.io/client-go"
	"k8s.io/client-go/kubernetes"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const defaultCSRDuration = time.Hour * 24 * 365

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type CustomerSigner struct {
	keyPem      []byte
	certPem     []byte
	certificate *x509.Certificate
	privateKey  crypto.Signer

	kubeClient  kubernetes.Interface
	csrInformer cache.SharedIndexInformer
	csrLister   certificateslisters.CertificateSigningRequestLister
	csrsSynced  cache.InformerSynced
	queue       workqueue.RateLimitingInterface
}

func NewCustomerSigner(opts *options.CertificateControllerOptions) (*CustomerSigner, error) {
	keyPem, err := os.ReadFile(opts.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	certPem, err := os.ReadFile(opts.SigningCertFile)
	if err != nil {
		return nil, err
	}
	certs, err := cert.ParseCertsPEM(certPem)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("error reading CA cert file %q: expected 1 certificate, found %d", opts.SigningCertFile, len(certs))
	}
	key, err := keyutil.ParsePrivateKeyPEM(keyPem)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("error reading CA key file %q: key did not implement crypto.Signer", opts.SigningKeyFile)
	}

	cs := &CustomerSigner{
		keyPem:      keyPem,
		certPem:     certPem,
		certificate: certs[0],
		privateKey:  priv,
	}

	return cs, nil
}

func (cs *CustomerSigner) Sign(certificateRequest *x509.CertificateRequest, usages []capi.KeyUsage, expirationSeconds *int32) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		klog.ErrorS(err, "Unable to generate a serial number")
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            certificateRequest.Subject,
		DNSNames:           certificateRequest.DNSNames,
		IPAddresses:        certificateRequest.IPAddresses,
		PublicKeyAlgorithm: certificateRequest.PublicKeyAlgorithm,
		PublicKey:          certificateRequest.PublicKey,
		Extensions:         certificateRequest.Extensions,
		ExtraExtensions:    certificateRequest.ExtraExtensions,
	}
	policy := PermissiveSigningPolicy{
		TTL:      cs.duration(expirationSeconds),
		Usages:   usages,
		Backdate: 5 * time.Minute,
		Short:    8 * time.Hour,
		Now:      time.Now,
	}
	if err := policy.apply(tmpl, cs.certificate.NotAfter); err != nil {
		klog.ErrorS(err, "Unable to apply signing policy")
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader, tmpl, cs.certificate, certificateRequest.PublicKey, cs.privateKey)
	if err != nil {
		klog.ErrorS(err, "Failed to sign certificate")
		return nil, err
	}
	return cert, nil
}

func (cs *CustomerSigner) duration(expirationSeconds *int32) time.Duration {
	if expirationSeconds == nil {
		return defaultCSRDuration
	}

	// honor requested duration is if it is less than the default TTL
	// use 10 min (2x hard coded backdate above) as a sanity check lower bound
	const min = 10 * time.Minute
	switch requestedDuration := time.Duration(*expirationSeconds) * time.Second; {
	case requestedDuration > defaultCSRDuration:
		return defaultCSRDuration
	case requestedDuration < min:
		return min
	default:
		return requestedDuration
	}
}
