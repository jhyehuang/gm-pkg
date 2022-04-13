package credentials

import (
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	cmtls "github.com/xhx/gm-pkg/crypto/tls"
	"github.com/xhx/gm-pkg/crypto/tls/credentials/helloworld"
	cmx509 "github.com/xhx/gm-pkg/crypto/x509"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port    = ":8090"
	address = "localhost:8090"
)

const (
	requestMsg  = "hello, I'm client"
	responseMsg = "hi, I'm server"
)

type server struct{}

func (s *server) SayHello(ctx context.Context, req *helloworld.HelloRequest) (*helloworld.HelloReply, error) {
	log.Printf("Received %s", req.Name)
	return &helloworld.HelloReply{Message: responseMsg}, nil
}

//tls certs
const (
	ca         = "testdata/cacert.pem"
	serverCert = "testdata/servercert.pem"
	serverKey  = "testdata/serverkey.pem"
	userCert   = "testdata/usercert.pem"
	userKey    = "testdata/userkey.pem"
)

//grpc server
func serverRun(t *testing.T) {
	signCert, err := cmtls.LoadX509KeyPair(serverCert, serverKey)
	require.NoError(t, err)

	certPool := cmx509.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	require.NoError(t, err)

	certPool.AppendCertsFromPEM(cacert)
	lis, err := net.Listen("tcp", port)
	require.NoError(t, err)

	creds := NewTLS(&cmtls.Config{
		ClientAuth:   cmtls.RequireAndVerifyClientCert,
		Certificates: []cmtls.Certificate{signCert},
		ClientCAs:    certPool,
	})

	s := grpc.NewServer(grpc.Creds(creds))
	helloworld.RegisterGreeterServer(s, &server{})
	err = s.Serve(lis)

	require.NoError(t, err)
}

func clientRun(t *testing.T, stop chan struct{}) {
	cert, err := cmtls.LoadX509KeyPair(userCert, userKey)
	require.NoError(t, err)

	certPool := cmx509.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	require.NoError(t, err)

	certPool.AppendCertsFromPEM(cacert)
	creds := NewTLS(&cmtls.Config{
		ServerName:   "chainmaker.org",
		Certificates: []cmtls.Certificate{cert},
		RootCAs:      certPool,
		ClientAuth:   cmtls.RequireAndVerifyClientCert,
	})
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	defer conn.Close()
	require.NoError(t, err)

	c := helloworld.NewGreeterClient(conn)
	r, err := c.SayHello(context.Background(), &helloworld.HelloRequest{Name: requestMsg})
	require.NoError(t, err)
	require.Equal(t, responseMsg, r.Message)

	stop <- struct{}{}
}

func Test_GrpcTlsWith2WayAuth(t *testing.T) {
	stop := make(chan struct{}, 1)
	go serverRun(t)
	time.Sleep(time.Second * 3) //wait for server start
	go clientRun(t, stop)
	<-stop
}
