package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	COLLECTION_MESSAGE_FOR_PATIENT = "collectionMessageForPatient"
	COLLECTION_MESSAGE_FOR_SHARING = "collectionMessageForSharing"
	// COLLECTION_MEDICALDATA_FOR_PATIENT = "collectionMedicalDataForPatient"
	// COLLECTION_MEDICALDATA_FOR_SHARING = "collectionMedicalDataForSharing"
	COLLECTION_MEDICALDATA_STORE = "collectionMedicalDataStore"
)

type MessageForPatientTrans struct {
	TransactionHash      string `json:"transaction_hash"`
	PatientPublicKeyHash string `json:"patient"` //the fieldtags are needed to keep case from bouncing around
	Hospital             string `json:"hospital"`
	MedicalDataID        string `json:"medical_data_id"` // 为演示添加的字段
	AuxStr               string `json:"aux"`             // 为演示添加的字段
	IsOld                bool   `json:"is_old"`          // 判断是新消息还是旧消息
}

type MessageForSharingTrans struct {
	TransactionHash      string `json:"transaction_hash"`
	VisitorPublicKeyHash string `json:"visitor"`         //the fieldtags are needed to keep case from bouncing around
	MedicalDataID        string `json:"medical_data_id"` // 为演示添加的字段
	AuxStr               string `json:"aux"`             // 为演示添加的字段
	IsOld                bool   `json:"is_old"`
}

type MedicalDataStoreTrans struct {
	MedicalDataID string `json:"medical_data_id"`
	Token         string `json:"token"`
	Ciphertext    string `json:"ciphertext"`
}

type MessageForPatient struct {
	ObjectType string `json:"docType"` //docType is used to distinguish the various types of objects in state database
	MessageForPatientTrans
}

type MessageForSharing struct {
	ObjectType string `json:"docType"` //docType is used to distinguish the various types of objects in state database
	MessageForSharingTrans
}

// type MedicalDataForPatient struct {
// 	ObjectType string `json:"docType"`
// 	api.MedicalDataForPatientTrans
// }

// type MedicalDataForSharing struct {
// 	ObjectType string `json:"docType"`
// 	api.MedicalDataForSharingTrans
// }

type MedicalDataStore struct {
	ObjectType string `json:"docType"`
	MedicalDataStoreTrans
}

type SmartContract struct {
	contractapi.Contract
}

// ===============================================
// 患者查询是否有属于自己的新医疗数据产生，目前支持返回一条数据用作演示，多条数据的话用CouchDB比较方便
// ===============================================

func (s *SmartContract) QueryMessage(ctx contractapi.TransactionContextInterface) (*MessageForPatientTrans, error) {
	clientIdentity := ctx.GetClientIdentity()
	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return nil, err
	}
	// 获取患者公钥
	clientCert, err := clientIdentity.GetX509Certificate()
	if err != nil {
		return nil, err
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
	if err != nil {
		return nil, err
	}
	// 验证client是否为患者组织Org2的成员
	if mspid != "Org2MSP" {
		fmt.Println("client's mspid is:", mspid)
		return nil, errors.New("client doesn't belong to the patient organization")
	}

	// 计算患者公钥
	patientPublicKeyStr := base64.RawStdEncoding.EncodeToString(publicKeyDer)
	publicKeyHash := ComputeCRH([]byte(patientPublicKeyStr))

	// 目前只支持一条新消息，后面的新消息会覆盖之前的消息，因为这里以用户公钥hash值作为key
	messageJSON, err := ctx.GetStub().GetPrivateData(COLLECTION_MESSAGE_FOR_PATIENT, publicKeyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find from message collection: %s", err.Error())
	}
	if messageJSON == nil {
		return nil, nil
	}

	messageForPatientList := new(MessageForPatient)
	if err = json.Unmarshal(messageJSON, &messageForPatientList); err != nil {
		return nil, err
	}

	result := new(MessageForPatientTrans)
	modifyMessageForPatient := new(MessageForPatient)
	// messageForPatient := messageForPatientList[1]
	if !messageForPatientList.IsOld {
		result = &MessageForPatientTrans{
			TransactionHash:      messageForPatientList.TransactionHash,
			PatientPublicKeyHash: messageForPatientList.PatientPublicKeyHash,
			Hospital:             messageForPatientList.Hospital,
			MedicalDataID:        messageForPatientList.MedicalDataID,
			AuxStr:               messageForPatientList.AuxStr,
		}
		messageForPatientList.IsOld = true
		modifyMessageForPatient = messageForPatientList
	}

	if result == nil {
		return nil, nil
	}

	newMessageForPatientJson, err := json.Marshal(modifyMessageForPatient)
	if err != nil {
		return nil, err
	}

	err = ctx.GetStub().PutPrivateData(COLLECTION_MESSAGE_FOR_PATIENT, publicKeyHash, newMessageForPatientJson)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ===============================================
// 被授权者查询是否有分享给自己的新的共享医疗数据
// ===============================================

func (s *SmartContract) QueryMessageForSharing(ctx contractapi.TransactionContextInterface) (*MessageForSharingTrans, error) {
	clientIdentity := ctx.GetClientIdentity()
	// 获取用户公钥
	clientCert, err := clientIdentity.GetX509Certificate()
	if err != nil {
		return nil, err
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
	if err != nil {
		return nil, err
	}

	// 计算用户公钥hash
	patientPublicKeyStr := base64.RawStdEncoding.EncodeToString(publicKeyDer)
	publicKeyHash := ComputeCRH([]byte(patientPublicKeyStr))

	// 目前只支持一条新消息，后面的新消息会覆盖之前的消息，因为这里以用户公钥hash值作为key
	messageJSON, err := ctx.GetStub().GetPrivateData(COLLECTION_MESSAGE_FOR_SHARING, publicKeyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find from message collection: %s", err.Error())
	}
	if messageJSON == nil {
		return nil, nil
	}

	messageForSharingList := new(MessageForSharing)
	if err = json.Unmarshal(messageJSON, &messageForSharingList); err != nil {
		return nil, err
	}

	result := new(MessageForSharingTrans)
	modifyMessageForSharing := new(MessageForSharing)
	if !messageForSharingList.IsOld {
		result = &MessageForSharingTrans{
			TransactionHash:      messageForSharingList.TransactionHash,
			VisitorPublicKeyHash: messageForSharingList.VisitorPublicKeyHash,
			MedicalDataID:        messageForSharingList.MedicalDataID,
			AuxStr:               messageForSharingList.AuxStr,
		}
		messageForSharingList.IsOld = true
		modifyMessageForSharing = messageForSharingList
	}
	if result == nil {
		return nil, nil
	}

	modifyMessageForSharingJson, err := json.Marshal(modifyMessageForSharing)
	if err != nil {
		return nil, err
	}

	err = ctx.GetStub().PutPrivateData(COLLECTION_MESSAGE_FOR_SHARING, publicKeyHash, modifyMessageForSharingJson)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ===============================================
// 医疗机构上传加密的原始医疗数据存入私有数据库
// ===============================================
func (s *SmartContract) UploadEncryptedMedicalData(ctx contractapi.TransactionContextInterface) error {
	clientIdentity := ctx.GetClientIdentity()
	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return err
	}
	// 验证是否为医疗机构的客户端
	if mspid != "Org1MSP" {
		fmt.Println("client's mspid is:", mspid)
		return errors.New("client doesn't belong to the medical organization")
	}
	// 获取Transient filed 的内容
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("Error getting transient: " + err.Error())
	}
	transJSON, ok := transMap["medical_data_for_patient"]
	if !ok {
		return fmt.Errorf("medical_data_for_patient not found in the transient map")
	}
	var medicalDataStoreTrans MedicalDataStoreTrans
	if err := json.Unmarshal(transJSON, &medicalDataStoreTrans); err != nil {
		return fmt.Errorf("unmarsahl trans json err: %v", err)
	}
	// 存入私有数据库
	medicalDataStore := &MedicalDataStore{
		ObjectType:            "MedicalDataStore",
		MedicalDataStoreTrans: medicalDataStoreTrans,
	}
	medicalDataStoreJson, err := json.Marshal(medicalDataStore)
	if err != nil {
		return fmt.Errorf("marsahl medical data json err: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataStore.MedicalDataID, medicalDataStoreJson)
	if err != nil {
		return fmt.Errorf("failed to store meidacal data for patient: %s", err.Error())
	}
	return nil
}

// ===============================================
// 患者上传加密的共享医疗数据存入私有数据库
// ===============================================
func (s *SmartContract) UploadEncryptedSharedMedicalData(ctx contractapi.TransactionContextInterface) error {
	clientIdentity := ctx.GetClientIdentity()
	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return err
	}
	// 验证是否为患者组织的客户端
	if mspid != "Org2MSP" {
		fmt.Println("client's mspid is:", mspid)
		return errors.New("client doesn't belong to the patient organization")
	}
	// 获取Transient filed 的内容
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("Error getting transient: " + err.Error())
	}
	transJSON, ok := transMap["medical_data_for_sharing"]
	if !ok {
		return fmt.Errorf("medical_data_for_sharing not found in the transient map")
	}
	var medicalDataStoreTrans MedicalDataStoreTrans
	if err := json.Unmarshal(transJSON, &medicalDataStoreTrans); err != nil {
		return fmt.Errorf("unmarsahl trans json err: %v", err)
	}
	// 存入私有数据库
	medicalDataStore := &MedicalDataStore{
		ObjectType:            "MedicalDataStore",
		MedicalDataStoreTrans: medicalDataStoreTrans,
	}
	medicalDataStoreJson, err := json.Marshal(medicalDataStore)
	if err != nil {
		return fmt.Errorf("marsahl shared medical data json err: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataStore.MedicalDataID, medicalDataStoreJson)
	if err != nil {
		return fmt.Errorf("failed to store shared meidacal data: %s", err.Error())
	}
	return nil
}

// ===============================================
// 存储医疗机构发送给病人的通知消息
// ===============================================
func (s *SmartContract) TransmitMessageToPatient(ctx contractapi.TransactionContextInterface) error {
	// clientIdentity := ctx.GetClientIdentity()
	// mspid, err := clientIdentity.GetMSPID()
	// if err != nil {
	// 	return err
	// }
	// 验证是否为医疗机构组织的客户端
	// if mspid != "Org1MSP" {
	// 	fmt.Println("client's mspid is:", mspid)
	// 	return errors.New("client doesn't belong to the medical organization")
	// }
	// 获取Transient filed 的内容
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("Error getting transient: " + err.Error())
	}
	transJSON, ok := transMap["message_for_patient"]
	if !ok {
		return fmt.Errorf("message_for_patient not found in the transient map")
	}
	var messageForPatientTrans MessageForPatientTrans
	if err := json.Unmarshal(transJSON, &messageForPatientTrans); err != nil {
		return fmt.Errorf("unmarsahl trans json err: %v", err)
	}
	// 存入私有数据库
	messageForPatient := &MessageForPatient{
		ObjectType:             "MessageForPatient",
		MessageForPatientTrans: messageForPatientTrans,
	}
	messageForPatientJson, err := json.Marshal(messageForPatient)
	if err != nil {
		return fmt.Errorf("marsahl message json for patient err: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(COLLECTION_MESSAGE_FOR_PATIENT, messageForPatient.PatientPublicKeyHash, messageForPatientJson)
	if err != nil {
		return fmt.Errorf("failed to store message for patient: %s", err.Error())
	}
	return nil
}

// ===============================================
// 存储患者共享医疗数据的通知消息
// ===============================================
func (s *SmartContract) TransmitMessageToShare(ctx contractapi.TransactionContextInterface) error {
	clientIdentity := ctx.GetClientIdentity()
	mspid, err := clientIdentity.GetMSPID()
	if err != nil {
		return err
	}
	// 验证是否为患者组织的客户端
	if mspid != "Org2MSP" {
		fmt.Println("client's mspid is:", mspid)
		return errors.New("client doesn't belong to the patient organization")
	}
	// 获取Transient filed 的内容
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("Error getting transient: " + err.Error())
	}
	transJSON, ok := transMap["message_for_sharing"]
	if !ok {
		return fmt.Errorf("message_for_sharing not found in the transient map")
	}
	var messageForSharingTrans MessageForSharingTrans
	if err := json.Unmarshal(transJSON, &messageForSharingTrans); err != nil {
		return fmt.Errorf("unmarsahl trans json err: %v", err)
	}
	// 通知被授权者，消息存入私有数据库
	messageForSharing := &MessageForSharing{
		ObjectType:             "MessageForSharing",
		MessageForSharingTrans: messageForSharingTrans,
	}
	messageForSharingJson, err := json.Marshal(messageForSharing)
	if err != nil {
		return fmt.Errorf("marsahl message json for sharing err: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(COLLECTION_MESSAGE_FOR_SHARING, messageForSharing.VisitorPublicKeyHash, messageForSharingJson)
	if err != nil {
		return fmt.Errorf("failed to store message for sharing: %s", err.Error())
	}
	return nil
}

// ===============================================
// 下载加密的原始医疗数据
// ===============================================
func (s *SmartContract) GetEncryptedMedicalData(ctx contractapi.TransactionContextInterface, medicalDataID, randomNumber string) (string, error) {
	// clientIdentity := ctx.GetClientIdentity()
	// // 获取患者公钥
	// clientCert, err := clientIdentity.GetX509Certificate()
	// if err != nil {
	// 	return nil, err
	// }
	// publicKeyDer, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
	// if err != nil {
	// 	return nil, err
	// }

	rawMedicalDataJson, err := ctx.GetStub().GetPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataID)
	if err != nil {
		return "", fmt.Errorf("failed to read from medical_data_store_collection %s", err.Error())
	}
	if rawMedicalDataJson == nil {
		return "", fmt.Errorf("%s does not exist", medicalDataID)
	}

	rawMedicalData := new(MedicalDataStore)
	if err = json.Unmarshal(rawMedicalDataJson, rawMedicalData); err != nil {
		return "", err
	}

	// 判断token是否符合
	// token := api.ComputePRF(hex.EncodeToString(publicKeyDer), randomNumber)
	token := ComputeCRH([]byte(randomNumber))
	if rawMedicalData.Token != "" && token != rawMedicalData.Token {
		return "", errors.New("token is invalid")
	}
	result := rawMedicalData
	// token置为空
	rawMedicalData.Token = ""
	if rawMedicalDataJson, err = json.Marshal(rawMedicalData); err != nil {
		return "", err
	}
	err = ctx.GetStub().PutPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataID, rawMedicalDataJson)
	if err != nil {
		return "", err
	}
	return result.Ciphertext, nil
}

// ===============================================
// 下载加密的共享医疗数据
// ===============================================
// func (s *SmartContract) GetSharingMedicalData(ctx contractapi.TransactionContextInterface, medicalDataID, randomNumber string) (*api.MedicalDataStoreTrans, error) {
// 	// 获取授权者公钥
// 	clientIdentity := ctx.GetClientIdentity()
// 	clientCert, err := clientIdentity.GetX509Certificate()
// 	if err != nil {
// 		return nil, err
// 	}
// 	publicKeyDer, err := x509.MarshalPKIXPublicKey(clientCert.PublicKey)
// 	if err != nil {
// 		return nil, err
// 	}

// 	rawMedicalDataJson, err := ctx.GetStub().GetPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataID)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get data from medical_data_store %s", err.Error())
// 	}
// 	if rawMedicalDataJson == nil {
// 		return nil, fmt.Errorf("%s does not exist", medicalDataID)
// 	}

// 	rawMedicalData := new(MedicalDataStore)
// 	if err = json.Unmarshal(rawMedicalDataJson, &rawMedicalData); err != nil {
// 		return nil, err
// 	}

// 	// 判断token是否符合
// 	token := ComputeCRH([]byte(hex.EncodeToString(publicKeyDer) + randomNumber))
// 	if rawMedicalData.Token == "" || token != rawMedicalData.Token {
// 		return nil, errors.New("token is invalid")
// 	}
// 	result := &api.MedicalDataStoreTrans{
// 		MedicalDataID: rawMedicalData.MedicalDataID,
// 		Token:         rawMedicalData.Token,
// 		Ciphertext:    rawMedicalData.Ciphertext,
// 	}
// 	// token置为空
// 	rawMedicalData.Token = ""
// 	if rawMedicalDataJson, err = json.Marshal(rawMedicalData); err != nil {
// 		return nil, err
// 	}
// 	err = ctx.GetStub().PutPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataID, rawMedicalDataJson)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return result, nil
// }

// ===============================================
// 更新医疗数据的访问token
// ===============================================
func (s *SmartContract) UpdateMedicalDataAccessToken(ctx contractapi.TransactionContextInterface, medicalDataID, token string) error {
	// 检查医疗数据id是否存在
	rawMedicalDataJson, err := ctx.GetStub().GetPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataID)
	if err != nil {
		return fmt.Errorf("failed to get data from medical_data_for_store %s", err.Error())
	}
	if rawMedicalDataJson == nil {
		return fmt.Errorf("%s does not exist", medicalDataID)
	}

	rawMedicalData := new(MedicalDataStore)
	if err = json.Unmarshal(rawMedicalDataJson, rawMedicalData); err != nil {
		return err
	}

	// 更新访问token
	rawMedicalData.Token = token
	if rawMedicalDataJson, err = json.Marshal(rawMedicalData); err != nil {
		return err
	}
	err = ctx.GetStub().PutPrivateData(COLLECTION_MEDICALDATA_STORE, medicalDataID, rawMedicalDataJson)
	if err != nil {
		return err
	}
	return nil
}

// ===============================================
// 目前先支持查询医疗数据的私有数据hash
// ===============================================
func (s *SmartContract) GetMedicalDataHash(ctx contractapi.TransactionContextInterface, collection string, medicalDataID string) (string, error) {

	// GetPrivateDataHash can use any collection deployed with the chaincode as input
	hashAsbytes, err := ctx.GetStub().GetPrivateDataHash(collection, medicalDataID)
	if err != nil {
		return "", fmt.Errorf("Failed to get public data hash:" + err.Error())
	} else if hashAsbytes == nil {
		return "", fmt.Errorf("medical data is does not exist: " + medicalDataID)
	}

	return string(hashAsbytes), nil
}

func ComputeCRH(r []byte) string {
	h := sha256.Sum256(r)
	return hex.EncodeToString(h[:])
}

func main() {

	chaincode, err := contractapi.NewChaincode(new(SmartContract))

	if err != nil {
		fmt.Printf("Error creating private pdmanage chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting private pdmanage chaincode: %s", err.Error())
	}

	// See chaincode.env.example
	// config := serverConfig{
	// 	CCID:    os.Getenv("CHAINCODE_ID"),
	// 	Address: os.Getenv("CHAINCODE_SERVER_ADDRESS"),
	// }

	// chaincode, err := contractapi.NewChaincode(&SmartContract{})

	// if err != nil {
	// 	fmt.Printf("error create mdmanage chaincode: %s", err.Error())
	// 	return
	// }

	// server := &shim.ChaincodeServer{
	// 	CCID:     config.CCID,
	// 	Address:  config.Address,
	// 	CC:       chaincode,
	// 	TLSProps: getTLSProperties(),
	// }

	// if err := server.Start(); err != nil {
	// 	fmt.Printf("error starting mdmanage chaincode server: %s", err.Error())
	// }
}
