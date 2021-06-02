module hyperledger/fabric-samples/mds/application/patient

go 1.14

require (
	github.com/hyperledger/fabric-sdk-go v1.0.0
	golang.org/x/net v0.0.0-20201021035429-f5854403a974 // indirect
	golang.org/x/sys v0.0.0-20210119212857-b64e53b001e4 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	hyperledger/fabric-samples/mds/api/go v1.0.0
	hyperledger/fabric-samples/mds/util/go v1.0.0
)

replace (
	hyperledger/fabric-samples/mds/api/go => ../../api/go
	hyperledger/fabric-samples/mds/util/go => ../../util/go
)
