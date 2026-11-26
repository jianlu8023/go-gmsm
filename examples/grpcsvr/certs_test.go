package grpcsvr

import (
	"crypto"
	"crypto/rand"
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

// ensureTestCerts 在 dir 下生成 grpcsvr 测试证书集：
// SM2 CA + sign（服务端签名）/encrypt（服务端加密）/user（客户端）证书，
// SAN = test.example.com（client 以 ServerName "test.example.com" 连接）。
// 已存在的文件不覆盖。
func ensureTestCerts(dir string) error {
	caCertPEM, caKeyPEM := testGenSM2("go-gmsm Test CA", nil, true,
		gmx509.KeyUsageCertSign|gmx509.KeyUsageCRLSign, nil, nil, nil, 1)
	testWriteFile(filepath.Join(dir, "ca.cert"), caCertPEM)
	testWriteFile(filepath.Join(dir, "ca.key"), caKeyPEM)

	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := gmx509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA: %v", err)
	}
	caPriv := testMustSM2Priv(caKeyPEM)

	signCertPEM, signKeyPEM := testGenSM2("test.example.com", []string{"test.example.com"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth, gmx509.ExtKeyUsageClientAuth},
		caCert, caPriv, 2)
	testWriteFile(filepath.Join(dir, "sign.cert"), signCertPEM)
	testWriteFile(filepath.Join(dir, "sign.key"), signKeyPEM)

	encCertPEM, encKeyPEM := testGenSM2("test.example.com", []string{"test.example.com"}, false,
		gmx509.KeyUsageKeyEncipherment, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageServerAuth},
		caCert, caPriv, 3)
	testWriteFile(filepath.Join(dir, "encrypt.cert"), encCertPEM)
	testWriteFile(filepath.Join(dir, "encrypt.key"), encKeyPEM)

	userCertPEM, userKeyPEM := testGenSM2("test.example.com", []string{"test.example.com"}, false,
		gmx509.KeyUsageDigitalSignature, []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth},
		caCert, caPriv, 4)
	testWriteFile(filepath.Join(dir, "user.cert"), userCertPEM)
	testWriteFile(filepath.Join(dir, "user.key"), userKeyPEM)

	return nil
}
