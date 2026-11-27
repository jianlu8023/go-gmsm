// Command gencerts regenerates the test certificates used by the gmtls
// examples/tests. It produces:
//
//   - examples/credentials/certs/* : SM2 CA + sign/encrypt/user certs,
//     valid for 10 years, SAN = test.example.com (the credentials example client
//     verifies ServerName "test.example.com").
//   - examples/websvr/certs/* : an RSA CA + RSA sign/auth certs and an SM2 CA +
//     SM2 sign/enc/auth certs, valid for 10 years, SAN = localhost (the
//     websvr client dials "localhost").
//
// It uses go-gmsm's own x509/sm2 packages so the produced SM2 certificates are
// byte-compatible with what gmtls parses.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	gmsm2 "github.com/jianlu8023/go-gmsm/sm2"
	gmx509 "github.com/jianlu8023/go-gmsm/x509"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// sm2KeyToPEM marshals a go-gmsm SM2 private key into the PKCS#8 "PRIVATE KEY"
// PEM block that go-gmsm's own LoadX509KeyPair / ParsePKCS8PrivateKey expects.
func sm2KeyToPEM(priv *gmsm2.PrivateKey) []byte {
	der, err := gmx509.MarshalSm2UnecryptedPrivateKey(priv)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// genSM2 creates an SM2 key and, if parentCert is nil, a self-signed CA;
// otherwise a leaf certificate signed by the CA. It returns (certPEM, keyPEM).
func genSM2(commonName string, dnsNames []string, isCA bool, keyUsage gmx509.KeyUsage, extUsages []gmx509.ExtKeyUsage, parentCert *gmx509.Certificate, caPriv *gmsm2.PrivateKey, serial int64) ([]byte, []byte) {
	priv, err := gmsm2.GenerateKey(rand.Reader)
	must(err)

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	template := &gmx509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"go-gmsm"},
			OrganizationalUnit: []string{"Test"},
			Country:            []string{"CN"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extUsages,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              dnsNames,
		SignatureAlgorithm:    gmx509.SM2WithSM3,
	}

	if isCA {
		template.SubjectKeyId = []byte{1, 2, 3, 4}
	}

	var parent *gmx509.Certificate
	var signer crypto.Signer
	if parentCert == nil {
		// self-signed
		parent = template
		signer = priv
	} else {
		parent = parentCert
		signer = caPriv
	}

	certPEM, err := gmx509.CreateCertificateToPem(template, parent, &priv.PublicKey, signer)
	must(err)

	return certPEM, sm2KeyToPEM(priv)
}

func writeFile(path string, data []byte) {
	must(os.MkdirAll(filepath.Dir(path), 0755))
	must(os.WriteFile(path, data, 0644))
	fmt.Printf("wrote %s\n", path)
}

func main() {
	base := "."
	if len(os.Args) > 1 {
		base = os.Args[1]
	}

	// ---------- credentials/certs (all SM2, single CA) ----------
	tc := filepath.Join(base, "examples/grpcsvr/certs")
	caCertPEM, caKeyPEM := genSM2("go-gmsm Test CA", nil, true,
		gmx509.KeyUsageCertSign|gmx509.KeyUsageCRLSign, nil, nil, nil, 1)
	writeFile(filepath.Join(tc, "ca.cert"), caCertPEM)
	writeFile(filepath.Join(tc, "ca.key"), caKeyPEM)

	// parse CA cert back so leaves can be signed by it
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := gmx509.ParseCertificate(caBlock.Bytes)
	must(err)
	// caPriv for signing leaves
	caPriv := mustSM2Priv(caKeyPEM)

	signCertPEM, signKeyPEM := genSM2("test.example.com", []string{"test.example.com"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth, gmx509.ExtKeyUsageClientAuth},
		caCert, caPriv, 2)
	writeFile(filepath.Join(tc, "sign.cert"), signCertPEM)
	writeFile(filepath.Join(tc, "sign.key"), signKeyPEM)

	encCertPEM, encKeyPEM := genSM2("test.example.com", []string{"test.example.com"}, false,
		gmx509.KeyUsageKeyEncipherment, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth},
		caCert, caPriv, 3)
	writeFile(filepath.Join(tc, "encrypt.cert"), encCertPEM)
	writeFile(filepath.Join(tc, "encrypt.key"), encKeyPEM)

	userCertPEM, userKeyPEM := genSM2("test.example.com", []string{"test.example.com"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth},
		caCert, caPriv, 4)
	writeFile(filepath.Join(tc, "user.cert"), userCertPEM)
	writeFile(filepath.Join(tc, "user.key"), userKeyPEM)

	// ---------- websvr/certs (RSA CA + SM2 CA) ----------
	wc := filepath.Join(base, "examples/websvr/certs")

	// RSA CA
	rsaCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	rsaCA := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-gmsm RSA Test CA", Organization: []string{"go-gmsm"}, Country: []string{"CN"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	rsaCADER, err := x509.CreateCertificate(rand.Reader, rsaCA, rsaCA, &rsaCAKey.PublicKey, rsaCAKey)
	must(err)
	writeFile(filepath.Join(wc, "RSA_CA.cer"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCADER}))
	writeFile(filepath.Join(wc, "RSA_CA.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(rsaCAKey)}))

	// RSA sign cert (localhost)
	rsaSignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	rsaSign := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"go-gmsm"}, Country: []string{"CN"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
	}
	rsaSignDER, err := x509.CreateCertificate(rand.Reader, rsaSign, rsaCA, &rsaSignKey.PublicKey, rsaCAKey)
	must(err)
	writeFile(filepath.Join(wc, "rsa_sign.cer"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaSignDER}))
	writeFile(filepath.Join(wc, "rsa_sign_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(rsaSignKey)}))

	// RSA auth cert (localhost)
	rsaAuthKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	rsaAuth := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"go-gmsm"}, Country: []string{"CN"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
	}
	rsaAuthDER, err := x509.CreateCertificate(rand.Reader, rsaAuth, rsaCA, &rsaAuthKey.PublicKey, rsaCAKey)
	must(err)
	writeFile(filepath.Join(wc, "rsa_auth_cert.cer"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaAuthDER}))
	writeFile(filepath.Join(wc, "rsa_auth_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(rsaAuthKey)}))

	// SM2 CA (for websvr)
	sm2CACertPEM, sm2CAKeyPEM := genSM2("go-gmsm SM2 Test CA", nil, true,
		gmx509.KeyUsageCertSign|gmx509.KeyUsageCRLSign, nil, nil, nil, 10)
	writeFile(filepath.Join(wc, "SM2_CA.cer"), sm2CACertPEM)
	writeFile(filepath.Join(wc, "SM2_CA.key"), sm2CAKeyPEM)

	sm2CABlock, _ := pem.Decode(sm2CACertPEM)
	sm2CACert, err := gmx509.ParseCertificate(sm2CABlock.Bytes)
	must(err)
	sm2CAPriv := mustSM2Priv(sm2CAKeyPEM)

	// SM2 sign cert (localhost)
	sm2SignCertPEM, sm2SignKeyPEM := genSM2("localhost", []string{"localhost"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth, gmx509.ExtKeyUsageClientAuth},
		sm2CACert, sm2CAPriv, 11)
	writeFile(filepath.Join(wc, "sm2_sign_cert.cer"), sm2SignCertPEM)
	writeFile(filepath.Join(wc, "sm2_sign_key.pem"), sm2SignKeyPEM)

	// SM2 enc cert (localhost)
	sm2EncCertPEM, sm2EncKeyPEM := genSM2("localhost", []string{"localhost"}, false,
		gmx509.KeyUsageKeyEncipherment, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth},
		sm2CACert, sm2CAPriv, 12)
	writeFile(filepath.Join(wc, "sm2_enc_cert.cer"), sm2EncCertPEM)
	writeFile(filepath.Join(wc, "sm2_enc_key.pem"), sm2EncKeyPEM)

	// SM2 auth cert (localhost)
	sm2AuthCertPEM, sm2AuthKeyPEM := genSM2("localhost", []string{"localhost"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth},
		sm2CACert, sm2CAPriv, 13)
	writeFile(filepath.Join(wc, "sm2_auth_cert.cer"), sm2AuthCertPEM)
	writeFile(filepath.Join(wc, "sm2_auth_key.pem"), sm2AuthKeyPEM)

	fmt.Printf("done.\n")
}

func mustMarshalPKCS8(key *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	return b
}

// mustSM2Priv parses a PKCS#8 "PRIVATE KEY" PEM produced by sm2KeyToPEM back
// into a go-gmsm *sm2.PrivateKey.
func mustSM2Priv(keyPEM []byte) *gmsm2.PrivateKey {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		panic("failed to decode sm2 key pem")
	}
	priv, err := gmx509.ParsePKCS8PrivateKey(block.Bytes, nil)
	must(err)
	return priv
}

// Local fmt shims removed; fmt is imported directly.
