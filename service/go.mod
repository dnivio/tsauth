module github.com/dnivio/approval-service

go 1.25.0

replace github.com/dnivio/contracts => ../contracts

require (
	github.com/dnivio/contracts v0.0.0
	github.com/google/uuid v1.6.0
	google.golang.org/grpc v1.81.1
)

require (
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
