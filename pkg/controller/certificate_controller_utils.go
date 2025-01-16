package controller

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	capi "k8s.io/api/certificates/v1"
)

var appServingKeyUsages = []capi.KeyUsage{
	capi.UsageDigitalSignature,
	capi.UsageKeyEncipherment,
	capi.UsageServerAuth,
}

// parseCSR extracts the CSR from the bytes and decodes it.
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func validateAppServingCSR(req *x509.CertificateRequest, usages []capi.KeyUsage) error {
	// 必须包含server auth
	if !container[capi.KeyUsage](capi.UsageServerAuth, usages) {
		return fmt.Errorf("permitted key usages - must include ['server auth']")
	}
	// 不能包含"digital signature", "key encipherment", "server auth"之外的键
	for _, usage := range usages {
		if !container[capi.KeyUsage](usage, appServingKeyUsages) {
			return fmt.Errorf("permitted key usages - must not include key usages beyond ['digital signature', 'key encipherment', 'server auth']")
		}
	}

	if len(req.DNSNames) == 0 && len(req.IPAddresses) == 0 {
		return fmt.Errorf("DNS or IP subjectAltName is required")
	}
	if len(req.EmailAddresses) > 0 {
		return fmt.Errorf("Email subjectAltName are not allowed")
	}
	if len(req.URIs) > 0 {
		return fmt.Errorf("URI subjectAltName are not allowed")
	}

	return nil
}

func container[T capi.KeyUsage | string](slice T, slices []T) bool {
	for _, item := range slices {
		if item == slice {
			return true
		}
	}
	return false
}

func isCertificateRequestApproved(csr *capi.CertificateSigningRequest) bool {
	approved := false
	denied := false
	for _, c := range csr.Status.Conditions {
		if c.Type == capi.CertificateApproved {
			approved = true
		}
		if c.Type == capi.CertificateDenied {
			denied = true
		}
	}
	return approved && !denied
}

func hasTrueCondition(csr *capi.CertificateSigningRequest, conditionType capi.RequestConditionType) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == conditionType {
			return true
		}
	}
	return false
}
