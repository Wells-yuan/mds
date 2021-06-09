package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	api "hyperledger/fabric-samples/mds/api/go"
	"hyperledger/fabric-samples/mds/util/go/goEncrypt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

var function string
var userName string
var patientPublicKeyStr string
var dataId string

var org1Path string

// var mspPath string
var connConfigPath string

// type OrgCertConfig struct {
// 	Url        string `json:"url"`
// 	CaName     string `json:"caName"`
// 	TlsCACerts struct {
// 		Pem []string `json:"pem"`
// 	} `json:"tlsCACerts"`
// }

// type ConnConfig struct {
// 	CertificateAuthorities OrgCertConfig `json:"certificateAuthorities"`
// }

func init() {
	org1Path = "../../../test-network/organizations/peerOrganizations/org1.example.com/"
	connConfigPath = filepath.Join(org1Path, "connection-org1.yaml")
	flag.StringVar(&function, "f", "", "choose function")
	flag.StringVar(&userName, "u", "", "the name of hospital ")
	flag.StringVar(&patientPublicKeyStr, "p", "", "the name of patient")
}

// 生成医疗数据produce事务
func TransactionCreateID(wallet *gateway.Wallet) {
	if patientPublicKeyStr == "" {
		log.Fatal("Please set patient's public key")
	}

	// 获取传入的原始医疗数据,传入的医疗数据为json格式
	if len(flag.Args()) != 1 {
		log.Fatal("Please set one parameter as medical data")
	}
	rawMedicalData := flag.Args()[0]
	var medicalDataMap map[string]string
	if err := json.Unmarshal([]byte(rawMedicalData), &medicalDataMap); err != nil {
		log.Fatalf("Unmarshal raw medical data err: %v", err)
	}

	// 获取app使用者的私钥
	userIdentity, err := wallet.Get(userName)
	if err != nil {
		log.Fatalf("get hospital identity err: %v", err)
	}
	privateKeyStr := userIdentity.(*gateway.X509Identity).Key()
	fmt.Println("private key pem is: ", privateKeyStr)
	privateKeyHexStr := hex.EncodeToString([]byte(privateKeyStr))
	// 获取app使用者的公钥
	publicKeyHex64Str, err := api.GetClientPublicKeyFromCert(userIdentity)
	if err != nil {
		log.Fatalln(err)
	}

	// 生成对称加密密钥
	// rand.Seed(time.Now().Unix())
	// r := strconv.Itoa(rand.Int())
	randomBinInt, err := rand.Int(rand.Reader, big.NewInt(100000000000000000))
	if err != nil {
		log.Fatalf("generate random numer err: %v", err)
	}
	r := randomBinInt.String()
	ek := api.ComputePRF(privateKeyHexStr, r)
	fmt.Println("ek is :", ek)
	fmt.Println("r is :", r)

	// 计算医疗数据唯一标识
	medicalDataID, _ := api.ComputeIDWithRawData(medicalDataMap, r)
	fmt.Println("medicaldata id is :", medicalDataID)

	// 对生成的医疗数据唯一标识进行数字签名
	signature, err := goEncrypt.EccSign([]byte(medicalDataID), []byte(privateKeyStr))
	if err != nil {
		log.Fatalf("sign medical data id err: %v", err)
	}
	signatureStr := hex.EncodeToString(signature)
	fmt.Println("signature is: ", signatureStr)

	// 加密对称密钥和随机数
	patientPublicKey, err := hex.DecodeString(patientPublicKeyStr)
	if err != nil {
		log.Fatalf("decode public key string err: %v", err)
	}
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: patientPublicKey,
	}
	// Fabric CA使用ECC椭圆曲线生成的公私密钥对
	publicKeyPem := pem.EncodeToMemory(&publicKeyBlock)
	fmt.Println("public key pem is: ", string(publicKeyPem))
	aux, err := goEncrypt.EccEncrypt(api.LinkEkAndR(ek, r), publicKeyPem)
	if err != nil {
		log.Fatalf("failed to encrypt ek and r data: %v", err)
	}

	// 对aux进行认证
	henc := api.ComputeCRH(aux)
	auth := api.ComputePRF(privateKeyHexStr, henc)

	// 计算承诺
	cmtA := api.GenCMTA(medicalDataID, signatureStr, patientPublicKeyStr, ek, r)
	cmtU := api.GenCMTU(medicalDataID, patientPublicKeyStr, ek, r)

	// 生成零知识证明
	fmt.Println("============ Starting generate produce proof ============")
	// gateway.Identity
	proof := api.GenProduceProof(medicalDataID, signatureStr, cmtA, cmtU, henc, auth, patientPublicKeyStr, privateKeyHexStr, ek, r)
	fmt.Println("============  Done ============")

	// 连接到Fabric 网络节点，获取智能合约实例
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(connConfigPath))),
		gateway.WithIdentity(wallet, userName),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	// 获得指定通道
	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	// 获取智能合约实例
	contract := network.GetContract("mdmanage")

	// 发起创建医疗数据的事务
	log.Println("--> Submit Transaction: TransactionCreateID, function creates a state of new medical data id")
	txID, err := contract.SubmitTransaction("CreateMedicalData", medicalDataID, signatureStr, cmtA, cmtU, hex.EncodeToString(aux), auth, proof)
	if err != nil {
		log.Fatalf("Failed to Submit TransactionCreateID: %v", err)
	}
	log.Println("the produce transaction id is: ", string(txID))

	// 加密原始医疗数据
	cryptText, err := goEncrypt.AesCtrEncrypt([]byte(rawMedicalData), []byte(ek[:32]))
	if err != nil {
		log.Fatalf("Failed to encrypt raw medical data: %v", err)
	}
	// 构造MedicalDataStore实例
	medicalDataForPatient := &api.MedicalDataStoreTrans{
		MedicalDataID: medicalDataID,
		Ciphertext:    base64.StdEncoding.EncodeToString(cryptText),
	}
	// 进行Base64编码
	medicalDataForPatientJson, err := json.Marshal(medicalDataForPatient)
	if err != nil {
		log.Fatalf("marshal medical data for patient err: %v", err)
	}
	// 准备传输的transient字段
	transMap := map[string][]byte{
		"medical_data_for_patient": medicalDataForPatientJson,
	}

	// 获取智能合约实例
	contract = network.GetContract("pdmanage")
	// 上传医疗数据到私有数据库
	uploadTransaction, err := contract.CreateTransaction("UploadEncryptedMedicalData", gateway.WithTransient(transMap))
	if err != nil {
		log.Fatalf("create upload transaction err: %v", err)
	}
	log.Println("--> Submit Transaction: UploadEncryptedMedicalData, function upload the encrypted raw medical data")
	result, err := uploadTransaction.Submit("UploadEncryptedMedicalData")
	if err != nil {
		log.Fatalf("Failed to Submit TransactionUpload: %v", err)
	}
	if result == nil {
		log.Println(string(transMap["medical_data_for_patient"]))
	} else {
		log.Println(string(result))
	}
	// 通知患者有新增的医疗数据
	// 计算事务hash
	messageForPatientTrans := api.MessageForPatientTrans{
		TransactionHash:      string(txID),
		PatientPublicKeyHash: api.ComputeCRH([]byte(patientPublicKeyStr)),
		Hospital:             publicKeyHex64Str,
		MedicalDataID:        medicalDataID,
		AuxStr:               hex.EncodeToString(aux),
	}
	messageForPatientJson, err := json.Marshal(messageForPatientTrans)
	if err != nil {
		log.Fatalf("marshal message for patient err: %v", err)
	}
	// 准备传输的transient字段
	transMap = map[string][]byte{
		"message_for_patient": []byte(messageForPatientJson),
	}
	// 将消息交由链码转发（也是存入私有数据库，由患者发送请求查询是否有新的医疗数据）
	transmitTransaction, err := contract.CreateTransaction("TransmitMessageToPatient", gateway.WithTransient(transMap))
	if err != nil {
		log.Fatalf("create transmit transaction err: %v", err)
	}
	log.Println("--> Submit Transaction: TransmitMessageToPatient, function forward message to patient")
	result, err = transmitTransaction.Submit("TransmitMessageToPatient")
	if err != nil {
		log.Fatalf("Failed to Submit TransmitMessageToPatient: %v", err)
	}
	if result == nil {
		log.Println(string(transMap["medical_data_for_patient"]))
	} else {
		log.Println(string(result))
	}
}

func TransactionQueryID(wallet *gateway.Wallet) {
	if dataId == "" {
		log.Fatal("Please set one medical data id")
	}

	// 连接到Fabric 网络节点，获取智能合约实例
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(connConfigPath))),
		gateway.WithIdentity(wallet, userName),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	// 获得指定通道
	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	// 获取智能合约实例
	contract := network.GetContract("mdmanage")

	log.Println("--> Evaluate Transaction: Query, function returns the state of medical data on the world state")
	result, err := contract.EvaluateTransaction("QueryMedicalData", dataId)
	if err != nil {
		log.Fatalf("Failed to evaluate TransactionQueryID: %v", err)
	}
	log.Println(string(result))
}

func TransactionQueryAllID(wallet *gateway.Wallet) {
	// 连接到Fabric 网络节点，获取智能合约实例
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(connConfigPath))),
		gateway.WithIdentity(wallet, userName),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	// 获得指定通道
	network, err := gw.GetNetwork("mychannel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	// 获取智能合约实例
	contract := network.GetContract("mdmanage")

	log.Println("--> Evaluate Transaction: QueryAll, function returns all the state of medical data on the world state")
	result, err := contract.EvaluateTransaction("QueryAllMedicalData", dataId)
	if err != nil {
		log.Fatalf("Failed to evaluate TransactionQueryID: %v", err)
	}
	log.Println(string(result))
}

// 将医疗数据标识上传到区块链，
func main() {

	flag.Parse()
	if userName == "" {
		log.Fatal("Please set user name")
	}
	if function == "" {
		log.Fatal("Please choose function")
	}
	// 获取身份
	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}
	if !wallet.Exists(userName) {
		log.Fatalf("%v doesn't exist", userName)
	}

	// 设置环境变量
	err = os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
	if err != nil {
		log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
	}

	log.Println("============ application starts ============")

	switch function {
	case "create":
		TransactionCreateID(wallet)
	case "query":
		TransactionQueryID(wallet)
	case "queryall":
		TransactionQueryAllID(wallet)
	}

	log.Println("============ application-golang ends ============")
}
