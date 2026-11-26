module github.com/jianlu8023/go-gmsm

go 1.22

require (
	// github.com/golang/protobuf v1.4.2
	// golang.org/x/crypto v0.0.0-20201012173705-84dcc777aaee
	// golang.org/x/net v0.0.0-20201010224723-4f7140c49acb
	// google.golang.org/grpc v1.31.0

	github.com/golang/protobuf v1.5.4
	golang.org/x/crypto v0.33.0
	golang.org/x/net v0.30.0
	google.golang.org/grpc v1.67.1
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.33.0
	golang.org/x/net => golang.org/x/net v0.35.0
	google.golang.org/grpc => google.golang.org/grpc v1.69.4
	google.golang.org/protobuf => google.golang.org/protobuf v1.36.7
)

require (
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	google.golang.org/protobuf v1.36.7 // indirect
)
