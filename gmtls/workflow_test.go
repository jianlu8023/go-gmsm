package gmtls

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
	"testing"
	"time"

	gmsm2 "github.com/jianlu8023/go-gmsm/sm2"
	gmx509 "github.com/jianlu8023/go-gmsm/x509"
)

// testCertDir 是测试证书目录
const testCertDir = "certs"

func TestMain(m *testing.M) {
	if err := ensureTestCerts(testCertDir); err != nil {
		fmt.Fprintln(os.Stderr, "generate test certs:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// testMust
func testMust(err error) {
	if err != nil {
		panic(err)
	}
}

// testWriteFile 写入证书/密钥文件；文件已存在则跳过（避免每次运行重新生成）。
func testWriteFile(path string, data []byte) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	testMust(os.MkdirAll(filepath.Dir(path), 0755))
	testMust(os.WriteFile(path, data, 0644))
	fmt.Printf("wrote %s\n", path)
}

// testSM2KeyToPEM 把 go-gmsm SM2 私钥序列化为 PKCS#8 "PRIVATE KEY" PEM，
// 与 LoadX509KeyPair 期望的格式一致。
func testSM2KeyToPEM(priv *gmsm2.PrivateKey) []byte {
	der, err := gmx509.MarshalSm2UnecryptedPrivateKey(priv)
	testMust(err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// testGenSM2 生成 SM2 密钥与证书（isCA 为自签 CA，否则由 parentCert/caPriv 签发）。
func testGenSM2(commonName string, dnsNames []string, isCA bool, keyUsage gmx509.KeyUsage, extUsages []gmx509.ExtKeyUsage, parentCert *gmx509.Certificate, caPriv *gmsm2.PrivateKey, serial int64) ([]byte, []byte) {
	priv, err := gmsm2.GenerateKey(rand.Reader)
	testMust(err)

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
		parent = template // self-signed
		signer = priv
	} else {
		parent = parentCert
		signer = caPriv
	}

	certPEM, err := gmx509.CreateCertificateToPem(template, parent, &priv.PublicKey, signer)
	testMust(err)

	return certPEM, testSM2KeyToPEM(priv)
}

// testMustSM2Priv 把 testSM2KeyToPEM 产出的 PEM 解析回 *gmsm2.PrivateKey。
func testMustSM2Priv(keyPEM []byte) *gmsm2.PrivateKey {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		panic("failed to decode sm2 key pem")
	}
	priv, err := gmx509.ParsePKCS8PrivateKey(block.Bytes, nil)
	testMust(err)
	return priv
}

func testMustMarshalPKCS8(key *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	testMust(err)
	return b
}

// ensureTestCerts 在 dir 下生成测试证书集：
// SM2_CA + sm2_sign/sm2_enc/sm2_auth，RSA_CA + rsa_sign。已存在的文件不覆盖。
func ensureTestCerts(dir string) error {
	// ---------- SM2 CA ----------
	sm2CACertPEM, sm2CAKeyPEM := testGenSM2("go-gmsm SM2 Test CA", nil, true,
		gmx509.KeyUsageCertSign|gmx509.KeyUsageCRLSign, nil, nil, nil, 10)
	testWriteFile(filepath.Join(dir, "SM2_CA.cer"), sm2CACertPEM)
	testWriteFile(filepath.Join(dir, "SM2_CA.key"), sm2CAKeyPEM)

	sm2CABlock, _ := pem.Decode(sm2CACertPEM)
	sm2CACert, err := gmx509.ParseCertificate(sm2CABlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse SM2 CA: %v", err)
	}
	sm2CAPriv := testMustSM2Priv(sm2CAKeyPEM)

	// SM2 sign cert (localhost)
	sm2SignCertPEM, sm2SignKeyPEM := testGenSM2("localhost", []string{"localhost"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth, gmx509.ExtKeyUsageClientAuth},
		sm2CACert, sm2CAPriv, 11)
	testWriteFile(filepath.Join(dir, "sm2_sign_cert.cer"), sm2SignCertPEM)
	testWriteFile(filepath.Join(dir, "sm2_sign_key.pem"), sm2SignKeyPEM)

	// SM2 enc cert (localhost)
	sm2EncCertPEM, sm2EncKeyPEM := testGenSM2("localhost", []string{"localhost"}, false,
		gmx509.KeyUsageKeyEncipherment, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth},
		sm2CACert, sm2CAPriv, 12)
	testWriteFile(filepath.Join(dir, "sm2_enc_cert.cer"), sm2EncCertPEM)
	testWriteFile(filepath.Join(dir, "sm2_enc_key.pem"), sm2EncKeyPEM)

	// SM2 auth cert (localhost)
	sm2AuthCertPEM, sm2AuthKeyPEM := testGenSM2("localhost", []string{"localhost"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth},
		sm2CACert, sm2CAPriv, 13)
	testWriteFile(filepath.Join(dir, "sm2_auth_cert.cer"), sm2AuthCertPEM)
	testWriteFile(filepath.Join(dir, "sm2_auth_key.pem"), sm2AuthKeyPEM)

	// ---------- RSA CA ----------
	rsaCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA CA key: %v", err)
	}
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
	if err != nil {
		return fmt.Errorf("create RSA CA: %v", err)
	}
	testWriteFile(filepath.Join(dir, "RSA_CA.cer"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCADER}))
	testWriteFile(filepath.Join(dir, "RSA_CA.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: testMustMarshalPKCS8(rsaCAKey)}))

	// RSA sign cert (localhost)
	rsaSignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA sign key: %v", err)
	}
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
	if err != nil {
		return fmt.Errorf("create RSA sign cert: %v", err)
	}
	testWriteFile(filepath.Join(dir, "rsa_sign.cer"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaSignDER}))
	testWriteFile(filepath.Join(dir, "rsa_sign_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: testMustMarshalPKCS8(rsaSignKey)}))

	return nil
}
