package grpcsvr

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/jianlu8023/go-gmsm/examples/echo"
	"github.com/jianlu8023/go-gmsm/gmtls"
	"github.com/jianlu8023/go-gmsm/gmtls/gmcredentials"
	"github.com/jianlu8023/go-gmsm/x509"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port    = ":50051"
	address = "localhost:50051"
)

var end chan bool

type server struct{}

func (s *server) Echo(ctx context.Context, req *echo.EchoRequest) (*echo.EchoResponse, error) {
	return &echo.EchoResponse{Result: req.Req}, nil
}

const ca = "certs/ca.cert"
const signCert = "certs/sign.cert"
const signKey = "certs/sign.key"
const encryptCert = "certs/encrypt.cert"
const encryptKey = "certs/encrypt.key"

const userCert = "certs/user.cert"
const userKey = "certs/user.key"

func serverRun() {
	signCert, err := gmtls.LoadX509KeyPair(signCert, signKey)
	if err != nil {
		log.Fatal(err)
	}

	encryptCert, err := gmtls.LoadX509KeyPair(encryptCert, encryptKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("fail to listen: %v", err)
	}
	creds := gmcredentials.NewTLS(&gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
		Certificates: []gmtls.Certificate{signCert, encryptCert},
		ClientCAs:    certPool,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	echo.RegisterEchoServer(s, &server{})
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Serve: %v", err)
	}
}

func clientRun() {
	cert, err := gmtls.LoadX509KeyPair(userCert, userKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	creds := gmcredentials.NewTLS(&gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		ServerName:   "test.example.com",
		Certificates: []gmtls.Certificate{cert},
		RootCAs:      certPool,
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
	})
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("cannot to connect: %v", err)
	}
	defer conn.Close()
	c := echo.NewEchoClient(conn)
	echoTest(c)
	end <- true
}

func echoTest(c echo.EchoClient) {
	r, err := c.Echo(context.Background(), &echo.EchoRequest{Req: "hello"})
	if err != nil {
		log.Fatalf("failed to echo: %v", err)
	}
	fmt.Printf("%s\n", r.Result)
}
