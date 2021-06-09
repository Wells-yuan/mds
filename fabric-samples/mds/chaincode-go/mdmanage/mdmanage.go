/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	api "hyperledger/fabric-samples/mds/api/go"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type serverConfig struct {
	CCID    string
	Address string
}

// SmartContract provides functions for managing a car
type SmartContract struct {
	contractapi.Contract
}

type MedicalData struct {
	Id      string   `json:"id"`
	Owner   string   `json:"owner"`
	Visitor []string `json:"visitor"`
}

type QueryResult struct {
	Key    string `json:"Key"`
	Record *MedicalData
}

// CreateCar adds a new car to the world state with given details
func (s *SmartContract) CreateMedicalData(ctx contractapi.TransactionContextInterface, medicalDataID, signatureStr, cmtA, cmtU, auxStr,
	auth, proof string) (string, error) {
	// 获取客户端所属组织的MSPID
	clientIdentity := ctx.GetClientIdentity()

	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return "", nil
	}

	// certTest.PublicKey
	// certTest.CheckSignature(certTest.SignatureAlgorithm, certTest.Signature, certTest.Signature)
	// certTest.CheckSignature(certTest.PublicKey)
	// switch pub := certTest.PublicKey.(type){
	// case *rsa.PublicKey:
	// 	publicKey, _ :=x509.ParsePKCS1PublicKey(x509.MarshalPKCS1PublicKey(pub))
	// }

	// certTest.CheckSignature(certTest.SignatureAlgorithm, )

	// 验证role是否为医疗机构组织Org1的成员
	if mspid != "Org1MSP" {
		fmt.Println("client's mspid is:", mspid)
		return "", errors.New("client doesn't belong to the medical organization")
	}

	// 验证对医疗数据唯一标识的签名
	clientCert, err := clientIdentity.GetX509Certificate()
	if err != nil {
		fmt.Println("check signature err: ", err)
		return "", err
	}

	signature, err := hex.DecodeString(signatureStr)
	if err != nil {
		log.Fatalf("decode signature err: %v", err)
	}
	if clientCert.CheckSignature(x509.ECDSAWithSHA256, []byte(medicalDataID), signature) != nil {
		return "", fmt.Errorf("check signature failed: %v", err)
	}

	// 判断医疗数据id是否已在世界状态中存在
	isExist, err := ctx.GetStub().GetState(medicalDataID)
	if err != nil || isExist != nil {
		return "", fmt.Errorf("%s has already existed", medicalDataID)
	}

	// 获取客户端唯一标识id
	// clientId, _ := clientIdentity.GetID()
	// fmt.Println("client's id is:", clinetID)
	// 验证proof是否正确
	aux, err := hex.DecodeString(auxStr)
	if err != nil {
		log.Fatalf("decode aux err: %v", err)
	}
	err = api.VerifyProduceProof(medicalDataID, signatureStr, cmtA, cmtU, api.ComputeCRH(aux), auth, proof)
	if err != nil {
		return "", errors.New("smart contract failed to verify produce proof ")
	}
	// 创建医疗数据
	medicalData := MedicalData{
		Id:      medicalDataID,
		Owner:   cmtA,
		Visitor: []string{cmtU},
	}
	medicalDataAsBytes, err := json.Marshal(medicalData)
	if err != nil {
		return "", fmt.Errorf("marshal medical data err: %v", err)
	}
	err = ctx.GetStub().PutState(medicalData.Id, medicalDataAsBytes)
	if err != nil {
		return "", err
	}
	return ctx.GetStub().GetTxID(), nil
}

func (s *SmartContract) CreateSharedMedicalData(ctx contractapi.TransactionContextInterface, medicalDataID, shareMedicalDataID, cmtA, cmtU1,
	cmtU2, auxStr, auth, proof, hashListStr, shareIndexStr string) (string, error) {
	// 获取客户端所属组织的MSPID
	clientIdentity := ctx.GetClientIdentity()

	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return "", err
	}

	// 验证客户端是否为医疗机构组织Org2的成员
	if mspid != "Org2MSP" {
		fmt.Println("client's mspid is:", mspid)
		return "", errors.New("client doesn't belong to the medical organization")
	}

	// 判断医疗数据id是否已在世界状态中存在
	isExist, err := ctx.GetStub().GetState(medicalDataID)
	if err != nil || isExist == nil {
		return "", fmt.Errorf("medical data id[%s] doesn't existed", medicalDataID)
	}
	isExist, err = ctx.GetStub().GetState(shareMedicalDataID)
	if err != nil || isExist != nil {
		return "", fmt.Errorf("shared medical data id[%s] already exists", shareMedicalDataID)
	}

	// 验证hashList能否生成相同的医疗数据id，以及共享医疗数据id计算的是否正确
	var hashList []string
	var shareIndex []int
	if err := json.Unmarshal([]byte(hashListStr), &hashList); err != nil {
		log.Fatalf("unmarshal hash list err: %v", err)
	}
	if err := json.Unmarshal([]byte(shareIndexStr), &shareIndex); err != nil {
		log.Fatalf("unmarshal share index err: %v", err)
	}
	if !api.CheckIDWithHashList(hashList, shareIndex, medicalDataID, shareMedicalDataID) {
		log.Fatalln("hash list faild to match the medical data id")
	}

	// 验证proof是否正确
	aux, err := hex.DecodeString(auxStr)
	if err != nil {
		log.Fatalf("decode aux err: %v", err)
	}
	err = api.VerifyShareProof(medicalDataID, shareMedicalDataID, cmtA, cmtU1, cmtU2, api.ComputeCRH(aux), auth, proof)
	if err != nil {
		return "", errors.New("smart contract failed to verify share proof ")
	}
	// 在世界状态中创建共享的医疗数据
	sharedMedicalData := MedicalData{
		Id:      shareMedicalDataID,
		Owner:   cmtU1,
		Visitor: []string{cmtU2},
	}
	sharedMedicalDataJson, err := json.Marshal(sharedMedicalData)
	if err != nil {
		return "", err
	}
	err = ctx.GetStub().PutState(shareMedicalDataID, sharedMedicalDataJson)
	if err != nil {
		return "", nil
	}
	return ctx.GetStub().GetTxID(), nil
}

func (s *SmartContract) UpdateSharedMedicalData(ctx contractapi.TransactionContextInterface, shareMedicalDataID, cmtU1, cmtU2, auxStr,
	auth, proof string) (string, error) {
	// 获取客户端所属组织的MSPID
	clientIdentity := ctx.GetClientIdentity()

	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return "", err
	}

	// 验证客户端是否为医疗机构组织Org2的成员
	if mspid != "Org2MSP" {
		fmt.Println("client's mspid is:", mspid)
		return "", errors.New("client doesn't belong to the medical organization")
	}

	// 判断医疗数据id是否已在世界状态中存在
	sharedMedicalDataStateStr, err := ctx.GetStub().GetState(shareMedicalDataID)
	if err != nil || sharedMedicalDataStateStr == nil {
		return "", fmt.Errorf("shared medical data id[%s] doesn't existed", shareMedicalDataID)
	}
	var sharedMedicalDataState MedicalData
	if err = json.Unmarshal(sharedMedicalDataStateStr, &sharedMedicalDataState); err != nil {
		return "", fmt.Errorf("unmarshal medical data err: %v", err)
	}

	// 判断承诺是否相等
	if cmtU1 != sharedMedicalDataState.Owner {
		return "", fmt.Errorf("cmt doesn't match: %v", err)
	}

	// 验证proof是否正确
	aux, err := hex.DecodeString(auxStr)
	if err != nil {
		log.Fatalf("decode aux err: %v", err)
	}
	err = api.VerifyUpdateProof(shareMedicalDataID, cmtU1, cmtU2, api.ComputeCRH(aux), auth, proof)
	if err != nil {
		return "", errors.New("smart contract failed to verify update proof ")
	}

	// 更新共享医疗数据的世界状态
	sharedMedicalDataState.Visitor = append(sharedMedicalDataState.Visitor, cmtU2)
	sharedMedicalDataJson, err := json.Marshal(sharedMedicalDataState)
	if err != nil {
		return "", err
	}
	err = ctx.GetStub().PutState(shareMedicalDataID, sharedMedicalDataJson)
	if err != nil {
		return "", nil
	}
	return ctx.GetStub().GetTxID(), nil
}

func (s *SmartContract) AccessTransaction(ctx contractapi.TransactionContextInterface, medicalDataID, cmtU, token, rHash, proof string) ([]byte, error) {
	// 判断医疗数据id是否已在世界状态中存在
	medicalDataStateStr, err := ctx.GetStub().GetState(medicalDataID)
	if err != nil || medicalDataStateStr == nil {
		return nil, fmt.Errorf("medical data id[%s] doesn't existed", medicalDataID)
	}
	var medicalDataState MedicalData
	if err = json.Unmarshal(medicalDataStateStr, &medicalDataState); err != nil {
		return nil, fmt.Errorf("unmarshal medical data state err: %v", err)
	}

	// 判断承诺是否相等
	equal := false
	for _, v := range medicalDataState.Visitor {
		if v == cmtU {
			equal = true
			break
		}
	}
	if !equal {
		return nil, fmt.Errorf("cmt doesn't match: %v", err)
	}

	// 验证proof是否正确
	err = api.VerifyAccessProof(medicalDataID, cmtU, token, proof)
	if err != nil {
		return nil, errors.New("smart contract failed to verify access proof ")
	}

	// 更新私有数据库中对应医疗数据id的访问token
	response := ctx.GetStub().InvokeChaincode("pdmanage", [][]byte{[]byte("UpdateMedicalDataAccessToken"), []byte(medicalDataID), []byte(rHash)}, "mychannel")
	return response.Payload, nil

}

func (s *SmartContract) QueryMedicalData(ctx contractapi.TransactionContextInterface, Id string) (*MedicalData, error) {
	medicalDataAsBytes, err := ctx.GetStub().GetState(Id)

	if err != nil {
		return nil, fmt.Errorf("failed to read from world state. %s", err.Error())
	}

	if medicalDataAsBytes == nil {
		return nil, fmt.Errorf("%s does not exist", Id)
	}

	medicalData := new(MedicalData)
	_ = json.Unmarshal(medicalDataAsBytes, medicalData)

	return medicalData, nil
}

func (s *SmartContract) QueryAllMedicalData(ctx contractapi.TransactionContextInterface) ([]QueryResult, error) {

	startKey := ""
	endKey := ""

	resultsIterator, err := ctx.GetStub().GetStateByRange(startKey, endKey)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	results := []QueryResult{}

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()

		if err != nil {
			return nil, err
		}

		medicalData := new(MedicalData)
		_ = json.Unmarshal(queryResponse.Value, medicalData)

		queryResult := QueryResult{Key: queryResponse.Key, Record: medicalData}
		results = append(results, queryResult)
	}

	return results, nil
}

func (s *SmartContract) QueryTransaction(ctx contractapi.TransactionContextInterface, txID string) string {
	fmt.Println("tanscation id is: ", txID)
	stub := ctx.GetStub()
	response := stub.InvokeChaincode("qscc", [][]byte{[]byte("GetTransactionByID"), []byte("mdmanage_1.0:6aeecdda20ee07cb527dd11c19a64cf36e117e8a0d35b0d5d9187988c3dae67c"), []byte(txID)}, stub.GetChannelID())
	payload := response.GetPayload()
	log.Println(string(payload))
	if payload == nil {
		return txID
	}
	return string(payload)
}

func main() {
	// See chaincode.env.example
	config := serverConfig{
		CCID:    os.Getenv("CHAINCODE_ID"),
		Address: os.Getenv("CHAINCODE_SERVER_ADDRESS"),
	}

	chaincode, err := contractapi.NewChaincode(&SmartContract{})

	if err != nil {
		fmt.Printf("error create mdmanage chaincode: %s", err.Error())
		return
	}

	server := &shim.ChaincodeServer{
		CCID:     config.CCID,
		Address:  config.Address,
		CC:       chaincode,
		TLSProps: getTLSProperties(),
	}

	if err := server.Start(); err != nil {
		fmt.Printf("error starting mdmanage chaincode server: %s", err.Error())
	}
}

func getTLSProperties() shim.TLSProperties {
	// Check if chaincode is TLS enabled
	tlsDisabledStr := getEnvOrDefault("CHAINCODE_TLS_DISABLED", "true")
	key := getEnvOrDefault("CHAINCODE_TLS_KEY", "")
	cert := getEnvOrDefault("CHAINCODE_TLS_CERT", "")
	clientCACert := getEnvOrDefault("CHAINCODE_CLIENT_CA_CERT", "")

	// convert tlsDisabledStr to boolean
	tlsDisabled := getBoolOrDefault(tlsDisabledStr, false)
	var keyBytes, certBytes, clientCACertBytes []byte
	var err error

	if !tlsDisabled {
		keyBytes, err = ioutil.ReadFile(key)
		if err != nil {
			log.Panicf("error while reading the crypto file: %s", err)
		}
		certBytes, err = ioutil.ReadFile(cert)
		if err != nil {
			log.Panicf("error while reading the crypto file: %s", err)
		}
	}
	// Did not request for the peer cert verification
	if clientCACert != "" {
		clientCACertBytes, err = ioutil.ReadFile(clientCACert)
		if err != nil {
			log.Panicf("error while reading the crypto file: %s", err)
		}
	}

	return shim.TLSProperties{
		Disabled:      tlsDisabled,
		Key:           keyBytes,
		Cert:          certBytes,
		ClientCACerts: clientCACertBytes,
	}
}

func getEnvOrDefault(env, defaultVal string) string {
	value, ok := os.LookupEnv(env)
	if !ok {
		value = defaultVal
	}
	return value
}

// Note that the method returns default value if the string
// cannot be parsed!
func getBoolOrDefault(value string, defaultVal bool) bool {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultVal
	}
	return parsed
}
