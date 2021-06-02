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
	"strings"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

var function string
var userName string
var medicalDataID string
var medicalDataInfo string
var indexStr string
var visitorStr string
var transactionInfo string // 为演示添加，正常应修改为transactionHash
var tokenInfo string

var org2Path string

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

type MedicalDataSummary struct {
	ID   string
	Ek   string
	R    string
	Role string
}

type SharedDataSummary struct {
	IdB      string
	Ek       string
	R        string
	IdA      string
	Index    []int
	Visitors []string
}

type AccessInfo struct {
	ID     string
	AuxStr string
}

type TokenSummary struct {
	ID    string
	R     string
	Token string
	Ek    string
}

func init() {
	org2Path = "../../../test-network/organizations/peerOrganizations/org2.example.com/"
	connConfigPath = filepath.Join(org2Path, "connection-org2.yaml")
	flag.StringVar(&function, "f", "", "choose function")
	flag.StringVar(&userName, "u", "", "the user name")
	flag.StringVar(&medicalDataID, "i", "", "the id of medical data")
	flag.StringVar(&indexStr, "k", "", "the key array of item about to share")
	flag.StringVar(&visitorStr, "v", "", "the visitor's public key")
	flag.StringVar(&medicalDataInfo, "s", "", "the summary of medical data")
	// flag.StringVar(&transactionHash, "t", "", "the hash of transaction")
	flag.StringVar(&transactionInfo, "t", "", "the info of transaction")
	flag.StringVar(&tokenInfo, "r", "", "the info of token")
}

func TransactionQueryID(wallet *gateway.Wallet) {
	if medicalDataID == "" {
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
	result, err := contract.EvaluateTransaction("QueryMedicalData", medicalDataID)
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
	result, err := contract.EvaluateTransaction("QueryAllMedicalData")
	if err != nil {
		log.Fatalf("Failed to evaluate TransactionQueryAllID: %v", err)
	}
	log.Println(string(result))
}

func TransactionPrintAllUserPublicKey(wallet *gateway.Wallet) {
	// 获取app使用者的公钥
	allUserId, _ := wallet.List()
	for _, userId := range allUserId {
		userIdentity, _ := wallet.Get(userId)
		patientPublicKeyStr, err := api.GetClientPublicKeyFromCert(userIdentity)
		if err != nil {
			fmt.Printf("parse %s's public key from cert err\n", userId)
		}
		fmt.Println(userId, "'s public key is: ", patientPublicKeyStr)
		publicKeyDer, err := base64.RawStdEncoding.DecodeString(patientPublicKeyStr)
		if err != nil {
			fmt.Printf("decode public key string err: %v\n", err)
		}
		publicKeyBlock := pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyDer,
		}
		fmt.Println(string(pem.EncodeToMemory(&publicKeyBlock)))

		privateKeyPem := userIdentity.(*gateway.X509Identity).Key()
		fmt.Println(userId, "'s privarte key is: ", privateKeyPem)
	}
}

// 检查是否有新属于自己的医疗数据、共享医疗数据
func TransactionCheckMessage(wallet *gateway.Wallet) {
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
	contract := network.GetContract("pdmanage")

	log.Println("--> Evaluate Transaction: QueryMessage")
	result, err := contract.EvaluateTransaction("QueryMessage")
	if err != nil {
		log.Fatalf("Failed to evaluate TransactionQueryID: %v", err)
	}
	log.Println(string(result))

	log.Println("--> Evaluate Transaction: QueryMessageForSharing")
	result, err = contract.EvaluateTransaction("QueryMessageForSharing")
	if err != nil {
		log.Fatalf("Failed to evaluate TransactionQueryID: %v", err)
	}
	log.Println(string(result))
}

// 生成医疗数据共享share事务
func TransactionCreateShareID(wallet *gateway.Wallet) {
	if medicalDataInfo == "" {
		log.Fatalln("please specify the medical data summary")
	}
	var medicalDataSummary MedicalDataSummary
	if err := json.Unmarshal([]byte(medicalDataInfo), &medicalDataSummary); err != nil {
		log.Fatalln("please check the json form of medical data summary, eg: '{\"id\":\"xx\",\"ek\":\"xx\",\"r\":\"xx\",\"role\":\"xx\"}'")
	}
	if indexStr == "" {
		log.Fatalln("please set key array as index")
	}
	if visitorStr == "" {
		log.Fatalln("please set the visitor")
	}
	// 把字符串解析为切片
	indexStrArr := strings.Split(indexStr, ",")

	// 获取传入的原始医疗数据
	if len(flag.Args()) != 1 {
		log.Fatal("Please set raw medical data")
	}
	rawMedicalData := flag.Args()[0]
	var rawMedicalDataMap map[string]string
	if err := json.Unmarshal([]byte(rawMedicalData), &rawMedicalDataMap); err != nil {
		log.Fatalf("Unmarshal raw medical data err: %v", err)
	}

	// 验证索引数组的合法性
	indexUnique := make(map[string]string, len(rawMedicalDataMap))
	for _, key := range indexStrArr {
		if _, ok := rawMedicalDataMap[key]; !ok {
			log.Fatalf("please set key array correctly, eg: 'aaa,bbb', %s doesn't exist", key)
		}
		if _, ok := indexUnique[key]; ok {
			fmt.Printf("key[%s] is repeated\n", key)
			continue
		}
		indexUnique[key] = key
	}

	// 获取app使用者的私钥
	userIdentity, err := wallet.Get(userName)
	if err != nil {
		log.Fatalf("get patient identity err: %v", err)
	}
	privateKeyStr := userIdentity.(*gateway.X509Identity).Key()
	fmt.Println("private key pem is: ", privateKeyStr)
	privateKeyHexStr := hex.EncodeToString([]byte(privateKeyStr))

	// 获取app使用者的公钥
	patientPublicKeyStr, err := api.GetClientPublicKeyFromCert(userIdentity)
	if err != nil {
		fmt.Printf("parse %s's public key from cert err\n", userName)
	}

	// 生成对称加密密钥
	randomBinInt, err := rand.Int(rand.Reader, big.NewInt(100000000000000000))
	if err != nil {
		log.Fatalf("generate random numer err: %v", err)
	}
	r := randomBinInt.String()
	ek := api.ComputePRF(privateKeyHexStr, r)
	fmt.Println("ek is :", ek)

	// 计算共享医疗数据唯一标识
	sharedMedicalDataId, hashList, shareIndex := api.ComputeShareIDWithRawDataAndIndex(medicalDataSummary.ID,
		rawMedicalDataMap, indexUnique, medicalDataSummary.R, r)

	// 加密对称密钥和随机数
	patientPublicKey, err := base64.RawStdEncoding.DecodeString(visitorStr)
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
	cmtA := api.GenCMTA(medicalDataSummary.ID, medicalDataSummary.Role, patientPublicKeyStr, medicalDataSummary.Ek, medicalDataSummary.R)
	cmtU1 := api.GenCMTU(sharedMedicalDataId, patientPublicKeyStr, ek, r)
	cmtU2 := api.GenCMTU(sharedMedicalDataId, visitorStr, ek, r)

	// 生成零知识证明
	fmt.Println("============ Starting generate share proof ============")
	proof := api.GenShareProof(medicalDataID, sharedMedicalDataId, cmtA, cmtU1, cmtU2, henc, auth, patientPublicKeyStr, visitorStr, privateKeyHexStr,
		medicalDataSummary.Ek, ek, medicalDataSummary.R, r, medicalDataSummary.Role)
	fmt.Println("============  Done  ============")

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

	// 发起创建共享医疗数据share事务
	hashList = append(hashList, api.ComputeCRH([]byte(medicalDataSummary.R)))
	hashList = append(hashList, api.ComputeCRH([]byte(r)))
	hashListJson, err := json.Marshal(hashList)
	if err != nil {
		log.Fatalf("marshal hash list err: %v", err)
	}
	shareIndexJson, err := json.Marshal(shareIndex)
	if err != nil {
		log.Fatalf("marshal shared index err: %v", err)
	}
	log.Println("--> Submit Transaction: CreateSharedMedicalData, function creates a state of shared medical data id")
	txID, err := contract.SubmitTransaction("CreateSharedMedicalData", medicalDataID, sharedMedicalDataId, cmtA, cmtU1, cmtU2, hex.EncodeToString(aux),
		auth, proof, string(hashListJson), string(shareIndexJson))
	if err != nil {
		log.Fatalf("Failed to Submit TransactionCreateShareID: %v", err)
	}
	log.Println("Create Shared Medical Data TxID is: ", txID)

	// 处理共享医疗数据
	var sharedMedicalData []string
	for _, index := range indexUnique {
		sharedMedicalData = append(sharedMedicalData, rawMedicalDataMap[index])
	}
	sharedMedicalDataJson, err := json.Marshal(sharedMedicalData)
	if err != nil {
		log.Fatalf("marshal shared medical data err: %v", err)
	}
	// 加密共享医疗数据
	cryptText, err := goEncrypt.AesCtrEncrypt(sharedMedicalDataJson, []byte(ek[:32]))
	if err != nil {
		log.Fatalf("Failed to encrypt shared medical data: %v", err)
	}
	// 构造MedicalDataForSharingTrans实例
	medicalDataForSharing := &api.MedicalDataStoreTrans{
		MedicalDataID: sharedMedicalDataId,
		Ciphertext:    base64.StdEncoding.EncodeToString(cryptText),
	}
	medicalDataForSharingJson, err := json.Marshal(medicalDataForSharing)
	if err != nil {
		log.Fatalf("marshal medical data for sharing err: %v", err)
	}
	// CLI中--transient后的参数必须用base64编码，因为这些参数以二进制传输
	// medicalDataForSharingBase64 := base64.StdEncoding.EncodeToString(medicalDataForSharingJson)
	// 准备传输的transient字段
	transMap := map[string][]byte{
		"medical_data_for_sharing": []byte(medicalDataForSharingJson),
	}

	// 获取智能合约实例
	contract = network.GetContract("pdmanage")
	// 上传共享医疗数据到私有数据库
	uploadTransaction, err := contract.CreateTransaction("UploadEncryptedSharedMedicalData", gateway.WithTransient(transMap))
	if err != nil {
		log.Fatalf("create upload transaction err: %v", err)
	}
	log.Println("--> Submit Transaction: UploadEncryptedSharedMedicalData, function upload the encrypted medical data for sharing")
	result, err := uploadTransaction.Submit("UploadEncryptedSharedMedicalData")
	if err != nil {
		log.Fatalf("Failed to Submit TransactionUpload: %v", err)
	}
	log.Println(string(result))

	// 通知被授权者有新增的医疗数据
	messageForSharingTrans := api.MessageForSharingTrans{
		TransactionHash:      string(txID),
		VisitorPublicKeyHash: api.ComputeCRH([]byte(visitorStr)),
		MedicalDataID:        sharedMedicalDataId,
		AuxStr:               hex.EncodeToString(aux),
	}
	messageForSharingJson, err := json.Marshal(messageForSharingTrans)
	if err != nil {
		log.Fatalf("marshal message for Sharing err: %v", err)
	}
	// messageForSharingBase64 := base64.StdEncoding.EncodeToString(messageForSharingJson)
	// 准备传输的transient字段
	transMap = map[string][]byte{
		"message_for_sharing": []byte(messageForSharingJson),
	}
	// 将消息交由链码转发（也是存入私有数据库，由被授权者发送请求查询是否有新的医疗数据）
	transmitTransaction, err := contract.CreateTransaction("TransmitMessageToShare", gateway.WithTransient(transMap))
	if err != nil {
		log.Fatalf("create transmit transaction err: %v", err)
	}
	log.Println("--> Submit Transaction: TransmitMessageToShare, function forward message to visitor")
	result, err = transmitTransaction.Submit("TransmitMessageToShare")
	if err != nil {
		log.Fatalf("Failed to Submit TransactionUpload: %v", err)
	}
	log.Println(string(result))

	// 构造shareDataSummary
	sharedDataSummary := SharedDataSummary{
		IdB:      sharedMedicalDataId,
		Ek:       ek,
		R:        r,
		IdA:      medicalDataID,
		Index:    shareIndex,
		Visitors: []string{visitorStr},
	}
	sharedDataSummaryJson, err := json.Marshal(sharedDataSummary)
	if err != nil {
		log.Fatalf("marshal shared data summary err: %v", err)
	}
	fmt.Println("new shared data summary is: ", string(sharedDataSummaryJson))
}

// 新增共享医疗数据的被授权者
func TransactionUpdateID(wallet *gateway.Wallet) {
	if medicalDataInfo == "" {
		log.Fatalln("please set the summary of shared medical data")
	}
	if visitorStr == "" {
		log.Fatalln("please set new visitor's public key")
	}
	// 解析数据
	var sharedDataSummary SharedDataSummary
	if err := json.Unmarshal([]byte(medicalDataInfo), &sharedDataSummary); err != nil {
		log.Fatalln("please check the json form of summary, eg: '{\"idB\":\"xx\",\"ek\":\"xx\",\"r\":\"xx\",\"idA\":\"xx\", \"index\":\"[1,4]\", \"visitors\":\"[xx]\"}'")
	}

	// 获取app使用者的私钥
	userIdentity, err := wallet.Get(userName)
	if err != nil {
		log.Fatalf("get patient identity err: %v", err)
	}
	privateKeyStr := userIdentity.(*gateway.X509Identity).Key()
	fmt.Println("private key pem is: ", privateKeyStr)
	privateKeyHexStr := hex.EncodeToString([]byte(privateKeyStr))

	// 获取app使用者的公钥
	patientPublicKeyStr, err := api.GetClientPublicKeyFromCert(userIdentity)
	if err != nil {
		fmt.Printf("parse %s's public key from cert err: %v\n", userName, err)
	}

	// 加密对称密钥和随机数
	visitorPublicKey, err := base64.RawStdEncoding.DecodeString(visitorStr)
	if err != nil {
		log.Fatalf("decode public key string err: %v", err)
	}
	visitorPublicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: visitorPublicKey,
	}
	// Fabric CA使用ECC椭圆曲线生成的公私密钥对
	visitorPublicKeyPem := pem.EncodeToMemory(&visitorPublicKeyBlock)
	fmt.Println("visitor's public key pem is: ", string(visitorPublicKeyPem))
	aux, err := goEncrypt.EccEncrypt(api.LinkEkAndR(sharedDataSummary.Ek, sharedDataSummary.R), visitorPublicKeyPem)
	if err != nil {
		log.Fatalf("failed to encrypt ek and r data: %v", err)
	}

	// 对aux进行认证
	henc := api.ComputeCRH(aux)
	auth := api.ComputePRF(privateKeyHexStr, henc)

	// 计算承诺
	cmtU1 := api.GenCMTU(sharedDataSummary.IdB, patientPublicKeyStr, sharedDataSummary.Ek, sharedDataSummary.R)
	cmtU2 := api.GenCMTU(sharedDataSummary.IdB, visitorStr, sharedDataSummary.Ek, sharedDataSummary.R)

	// 生成零知识证明
	fmt.Println("============ Starting generate update proof ============")
	// gateway.Identity
	proof := api.GenUpdateProof(sharedDataSummary.IdB, cmtU1, cmtU2, henc, auth, patientPublicKeyStr, visitorStr, privateKeyHexStr,
		sharedDataSummary.Ek, sharedDataSummary.R)
	fmt.Println("============  Done  ============")

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

	// 发起更新共享医疗数据update事务
	log.Println("--> Submit Transaction: UpdateSharedMedicalData, function add visitor of shared medical data id")
	txID, err := contract.SubmitTransaction("UpdateSharedMedicalData", sharedDataSummary.IdB, cmtU1, cmtU2, hex.EncodeToString(aux),
		auth, proof)
	if err != nil {
		log.Fatalf("Failed to Submit UpdateSharedMedicalData: %v", err)
	}
	log.Println("Update Shared Medical Data TxID is: ", txID)

	// 给新增的被授权者发送通知消息
	messageForSharingTrans := api.MessageForSharingTrans{
		TransactionHash:      string(txID),
		VisitorPublicKeyHash: api.ComputeCRH([]byte(visitorStr)),
		MedicalDataID:        sharedDataSummary.IdB,
		AuxStr:               hex.EncodeToString(aux),
	}

	messageForSharingJson, err := json.Marshal(messageForSharingTrans)
	if err != nil {
		log.Fatalf("marshal message for Sharing err: %v", err)
	}
	// 准备传输的transient字段
	transMap := map[string][]byte{
		"message_for_sharing": []byte(messageForSharingJson),
	}

	// 获取智能合约实例
	contract = network.GetContract("pdmanage")
	// 将消息交由链码转发（也是存入私有数据库，由被授权者发送请求查询是否有新的医疗数据）
	transmitTransaction, err := contract.CreateTransaction("TransmitMessageToShare", gateway.WithTransient(transMap))
	if err != nil {
		log.Fatalf("create transmit transaction err: %v", err)
	}
	log.Println("--> Submit Transaction: TransmitMessageToShare, function forward message to visitor")
	result, err := transmitTransaction.Submit("TransmitMessageToShare")
	if err != nil {
		log.Fatalf("Failed to Submit TransactionUpload: %v", err)
	}
	log.Println(string(result))

	// sharedDataSummary
	sharedDataSummary.Visitors = append(sharedDataSummary.Visitors, visitorStr)
	sharedDataSummaryJson, err := json.Marshal(sharedDataSummary)
	if err != nil {
		log.Fatalf("marshal shared data summary err: %v", err)
	}
	log.Print(string(sharedDataSummaryJson))
}

// 为医疗数据生成访问token
func TransactionAccessID(wallet *gateway.Wallet) {
	if transactionInfo == "" {
		log.Fatalln("please set the info of transaction, eg: '{\"medical_data_id\":\"xxx\",\"ek\":\"xx\",\"r\":\"xx\"}'")
	}

	var accessInfo AccessInfo
	if err := json.Unmarshal([]byte(transactionInfo), &accessInfo); err != nil {
		log.Fatalf("umarshal transaction info err: %v", err)
	}

	// 获取app使用者的公钥
	userIdentity, err := wallet.Get(userName)
	if err != nil {
		log.Fatalf("get patient identity err: %v", err)
	}
	patientPublicKeyStr, err := api.GetClientPublicKeyFromCert(userIdentity)
	if err != nil {
		fmt.Printf("parse %s's public key from cert err: %v\n", userName, err)
	}
	patientPublicKey, err := base64.RawStdEncoding.DecodeString(patientPublicKeyStr)
	if err != nil {
		log.Fatalf("decode public key string err: %v", err)
	}
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: patientPublicKey,
	}
	// Fabric CA使用ECC椭圆曲线生成的公私密钥对
	publicKeyPem := pem.EncodeToMemory(&publicKeyBlock)

	// 解密字符串，获取ek和r
	aux, err := hex.DecodeString(accessInfo.AuxStr)
	if err != nil {
		log.Fatalf("decode aux str err: %v", err)
	}
	plaintext, err := goEncrypt.EccDecrypt(aux, publicKeyPem)
	if err != nil {
		log.Fatalf("failed to decrypt aux string: %v", err)
	}
	var linkKey api.LinkKey
	if err := json.Unmarshal(plaintext, &linkKey); err != nil {
		log.Fatalf("unmarshal link key err: %v", err)
	}

	// 生成token
	randomBinInt, err := rand.Int(rand.Reader, big.NewInt(100000000000000000))
	if err != nil {
		log.Fatalf("generate random numer err: %v", err)
	}
	r := randomBinInt.String()
	token := api.ComputePRF(patientPublicKeyStr, r)
	fmt.Println("token is :", token)

	// 计算承诺
	cmtU := api.GenCMTU(accessInfo.ID, patientPublicKeyStr, linkKey.Ek, linkKey.R)

	// 生成零知识证明
	fmt.Println("============ Starting generate access proof ============")
	proof := api.GenAccessProof(accessInfo.ID, cmtU, token, patientPublicKeyStr, linkKey.Ek, linkKey.R, r)
	fmt.Println("============  Done  ============")

	// 展示使用
	rHash := api.ComputeCRH([]byte(r))

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

	// 发起访问医疗数据的事务
	log.Println("--> Submit Transaction: AccessTransaction, function update token for medical data id")
	result, err := contract.SubmitTransaction("AccessTransaction", accessInfo.ID, cmtU, token, rHash, proof)
	if err != nil {
		log.Fatalf("Failed to Submit TransactionCreateID: %v", err)
	}
	log.Println(string(result))

	// 生成tokenSummary
	tokenSummary := TokenSummary{
		ID:    accessInfo.ID,
		Token: token,
		R:     r,
		Ek:    linkKey.Ek,
	}
	tokenSummaryJson, err := json.Marshal(tokenSummary)
	if err != nil {
		log.Fatalf("marshal token summary err: %v", err)
	}
	log.Println(string(tokenSummaryJson))
}

// 为医疗数据生成访问token
func TransactionDownloadID(wallet *gateway.Wallet) {
	if tokenInfo == "" {
		log.Fatalln("please set token info, eg:'{\"id\":\"xx\",\"token\":\"xx\",\"r\":\"xx\",\"ek\":\"xx\"}'")
	}
	var tokenSummary TokenSummary
	if err := json.Unmarshal([]byte(tokenInfo), &tokenSummary); err != nil {
		log.Fatalf("umarshal token info err: %v", err)
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
	contract := network.GetContract("pdmanage")

	// 发起下载医疗数据的事务
	log.Println("--> Submit Transaction: GetEncryptedMedicalData, function download encrypted medicaldata")
	encryptedMedicalData, err := contract.EvaluateTransaction("GetEncryptedMedicalData", tokenSummary.ID, tokenSummary.R)
	if err != nil {
		log.Fatalf("Failed to Submit GetEncryptedMedicalData: %v", err)
	}
	log.Println(string(encryptedMedicalData))

	// 解密下载的医疗数据
	encryptedMedicalDataByte, err := base64.StdEncoding.DecodeString(string(encryptedMedicalData))
	if err != nil {
		log.Fatalf("decode encrypted medical data err: %v", err)
	}
	result, err := goEncrypt.AesCtrDecrypt(encryptedMedicalDataByte, []byte(tokenSummary.Ek[:32]))
	if err != nil {
		log.Fatalf("decrypt medical data err: %v", err)
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
	case "query":
		TransactionQueryID(wallet)
	case "queryall":
		TransactionQueryAllID(wallet)
	case "print":
		TransactionPrintAllUserPublicKey(wallet)
	case "check":
		TransactionCheckMessage(wallet)
	case "share":
		TransactionCreateShareID(wallet)
	case "updata":
		TransactionUpdateID(wallet)
	case "access":
		TransactionAccessID(wallet)
	case "download":
		TransactionDownloadID(wallet)
	}

	log.Println("============ application-golang ends ============")
}
