package websvr

import (
	"crypto/tls"
	x "crypto/x509"
	"io/ioutil"

	"github.com/jianlu8023/go-gmsm/tlcp"
	"github.com/jianlu8023/go-gmsm/x509"
)

const (
	rsaCertPath     = "./certs/rsa_sign.cer"
	rsaKeyPath      = "./certs/rsa_sign_key.pem"
	RSACaCertPath   = "./certs/RSA_CA.cer"
	RSAAuthCertPath = "./certs/rsa_auth_cert.cer"
	RSAAuthKeyPath  = "./certs/rsa_auth_key.pem"
	SM2CaCertPath   = "./certs/SM2_CA.cer"
	SM2AuthCertPath = "./certs/sm2_auth_cert.cer"
	SM2AuthKeyPath  = "./certs/sm2_auth_key.pem"
	sm2SignCertPath = "./certs/sm2_sign_cert.cer"
	sm2SignKeyPath  = "./certs/sm2_sign_key.pem"
	sm2EncCertPath  = "./certs/sm2_enc_cert.cer"
	sm2EncKeyPath   = "./certs/sm2_enc_key.pem"
)

// RSA配置
func loadRsaConfig() (*tlcp.Config, error) {
	cert, err := tlcp.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	return &tlcp.Config{Certificates: []tlcp.Certificate{cert}}, nil
}

// SM2配置
func loadSM2Config() (*tlcp.Config, error) {
	sigCert, err := tlcp.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := tlcp.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err
	}
	return &tlcp.Config{
		GMSupport:    &tlcp.GMSupport{},
		Certificates: []tlcp.Certificate{sigCert, encCert},
	}, nil
}

// 切换GMSSL/TSL
func loadAutoSwitchConfig() (*tlcp.Config, error) {
	rsaKeypair, err := tlcp.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	sigCert, err := tlcp.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := tlcp.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err

	}
	return tlcp.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
}

// 双向身份认证 服务端配置
func loadServerMutualTLCPAuthConfig() (*tlcp.Config, error) {
	// 签名密钥对/证书 和 加密密钥对/证书
	sigCert, err := tlcp.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := tlcp.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err

	}

	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tlcp.Config{
		GMSupport:    tlcp.NewGMSupport(),
		Certificates: []tlcp.Certificate{sigCert, encCert},
		ClientCAs:    certPool,
		ClientAuth:   tlcp.RequireAndVerifyClientCert,
	}, nil
}

// 要求客户端身份认证
func loadAutoSwitchConfigClientAuth() (*tlcp.Config, error) {
	config, err := loadAutoSwitchConfig()
	if err != nil {
		return nil, err
	}
	// 设置需要客户端证书请求，标识需要进行客户端的身份认证
	config.ClientAuth = tlcp.RequireAndVerifyClientCert
	return config, nil
}

// 获取 客户端服务端双向身份认证 配置
func bothAuthConfig() (*tlcp.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tlcp.LoadX509KeyPair(SM2AuthCertPath, SM2AuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tlcp.Config{
		GMSupport:          &tlcp.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []tlcp.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func singleSideAuthConfig() (*tlcp.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tlcp.Config{
		GMSupport: &tlcp.GMSupport{},
		RootCAs:   certPool,
	}, nil
}

// 获取 客户端服务端双向身份认证 配置
func rsaBothAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(RSAAuthCertPath, RSAAuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func rsaSingleSideAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		MaxVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}
