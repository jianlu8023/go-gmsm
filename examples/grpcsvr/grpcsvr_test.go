package grpcsvr

import (
	"testing"
	"time"
)

func Test_grpc(t *testing.T) {
	end = make(chan bool, 64)
	go serverRun()
	time.Sleep(1000000)
	go clientRun()
	<-end
}
