package api

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_produce -lzk_share -lzk_update -lzk_access -lff  -lsnark -lstdc++ -lgmp -lgmpxx
#include "producecgo.hpp"
#include "sharecgo.hpp"
#include "updatecgo.hpp"
#include "accesscgo.hpp"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

type MessageForPatientTrans struct {
	TransactionHash      string `json:"transaction_hash"`
	PatientPublicKeyHash string `json:"patient"` //the fieldtags are needed to keep case from bouncing around
	Hospital             string `json:"hospital"`
	MedicalDataID        string `json:"id"`     // 为演示添加的字段
	AuxStr               string `json:"aux"`    // 为演示添加的字段
	IsOld                bool   `json:"is_old"` // 判断是新消息还是旧消息
}

type MessageForSharingTrans struct {
	TransactionHash      string `json:"transaction_hash"`
	VisitorPublicKeyHash string `json:"visitor"` //the fieldtags are needed to keep case from bouncing around
	MedicalDataID        string `json:"id"`      // 为演示添加的字段
	AuxStr               string `json:"aux"`     // 为演示添加的字段
	IsOld                bool   `json:"is_old"`
}

// type MedicalDataForPatientTrans struct {
// 	MedicalDataID string `json:"medical_data_id"`
// 	Token         string `json:"token"`
// 	Ciphertext    string `json:"ciphertext"`
// 	Creator       string `json:"creator"`
// }

// type MedicalDataForSharingTrans struct {
// 	MedicalDataID string `json:"medical_data_id"`
// 	Token         string `json:"token"`
// 	Ciphertext    string `json:"ciphertext"`
// }

type MedicalDataStoreTrans struct {
	MedicalDataID string `json:"id"`
	Token         string `json:"token"`
	Ciphertext    string `json:"ciphertext"`
}

type LinkKey struct {
	Ek string
	R  string
}

func timeCost(function string) func() {
	start := time.Now()
	return func() {
		tc := time.Since(start)
		fmt.Printf("%s Proof Use Time: %v\n", function, tc)
	}
}

// 对客户端公私钥进行解析，返回字符串
func ParseKeyToStringFromPem() {

}

//ComputePRF生成sn 调用c的sha256函数  （go的sha256函数与c有一些区别）
func ComputePRF(sk, r string) string {
	skC := C.CString(sk)
	defer C.free(unsafe.Pointer(skC))

	rC := C.CString(r)
	defer C.free(unsafe.Pointer(rC))

	resC := C.computePRF(skC, rC)
	resGo := C.GoString(resC)
	return resGo
}

// func ComputePRF(sk []byte, r []byte) []byte {
// 	skC := C.CString(hex.EncodeToString(sk))
// 	defer C.free(unsafe.Pointer(skC))

// 	rC := C.CString(hex.EncodeToString(r))
// 	defer C.free(unsafe.Pointer(rC))

// 	resC := C.computePRF(skC, rC)
// 	resGo := C.GoString(resC)
// 	res, _ := hex.DecodeString(resGo)
// 	return res
// }

func ComputeCRH(r []byte) string {
	h := sha256.Sum256(r)
	return hex.EncodeToString(h[:])
}

// func ComputeCRH(r string) []byte {
// 	sha256Ins := sha256.New()
// 	sha256Ins.Write([]byte(r))
// 	return sha256Ins.Sum(nil)
// }

//GenCMT生成CMT 调用c的sha256函数  （go的sha256函数与c有一些区别）
// char *id_string, char *role_string, char *pk_string, char *ek_string, char *r_string
func GenCMTA(id, role, pk, ek, r string) string {

	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	roleC := C.CString(role)
	defer C.free(unsafe.Pointer(roleC))
	pkC := C.CString(pk)
	defer C.free(unsafe.Pointer(pkC))
	ekC := C.CString(ek)
	defer C.free(unsafe.Pointer(ekC))
	rC := C.CString(r)
	defer C.free(unsafe.Pointer(rC))

	cmtAC := C.genCMTA(idC, roleC, pkC, ekC, rC)
	cmtAGo := C.GoString(cmtAC)
	return cmtAGo
}

// func GenCMTA(id, role, pk, ek, r string) []byte {

// 	idC := C.CString(hex.EncodeToString(id))
// 	defer C.free(unsafe.Pointer(idC))
// 	roleC := C.CString(hex.EncodeToString(role))
// 	defer C.free(unsafe.Pointer(roleC))
// 	pkC := C.CString(hex.EncodeToString(pk))
// 	defer C.free(unsafe.Pointer(pkC))
// 	ekC := C.CString(hex.EncodeToString(ek))
// 	defer C.free(unsafe.Pointer(ekC))
// 	rC := C.CString(hex.EncodeToString(r))
// 	defer C.free(unsafe.Pointer(rC))

// 	cmtAC := C.genCMTA(idC, roleC, pkC, ekC, rC)
// 	cmtAGo := C.GoString(cmtAC)
// 	res, _ := hex.DecodeString(cmtAGo)
// 	return res
// }

func GenCMTU(id, pk, ek, r string) string {

	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	pkC := C.CString(pk)
	defer C.free(unsafe.Pointer(pkC))
	ekC := C.CString(ek)
	defer C.free(unsafe.Pointer(ekC))
	rC := C.CString(r)
	defer C.free(unsafe.Pointer(rC))

	cmtUC := C.genCMTU(idC, pkC, ekC, rC)
	cmtUGo := C.GoString(cmtUC)
	return cmtUGo
}

// func GenCMTU(id, pk, ek, r []byte) []byte {

// 	idC := C.CString(hex.EncodeToString(id))
// 	defer C.free(unsafe.Pointer(idC))
// 	pkC := C.CString(hex.EncodeToString(pk))
// 	defer C.free(unsafe.Pointer(pkC))
// 	ekC := C.CString(hex.EncodeToString(ek))
// 	defer C.free(unsafe.Pointer(ekC))
// 	rC := C.CString(hex.EncodeToString(r))
// 	defer C.free(unsafe.Pointer(rC))

// 	cmtUC := C.genCMTU(idC, pkC, ekC, rC)
// 	cmtUGo := C.GoString(cmtUC)
// 	res, _ := hex.DecodeString(cmtUGo)
// 	return res
// }

func GenProduceProof(id, role, cmtA, cmtU, henc, auth, pk, sk, ek, r string) string {
	defer timeCost("Generate Produce")()
	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	roleC := C.CString(role)
	defer C.free(unsafe.Pointer(roleC))
	cmtAC := C.CString(cmtA)
	defer C.free(unsafe.Pointer(cmtAC))
	cmtUC := C.CString(cmtU)
	defer C.free(unsafe.Pointer(cmtUC))
	hencC := C.CString(henc)
	defer C.free(unsafe.Pointer(hencC))
	authC := C.CString(auth)
	defer C.free(unsafe.Pointer(authC))
	pkC := C.CString(pk)
	defer C.free(unsafe.Pointer(pkC))
	skC := C.CString(sk)
	defer C.free(unsafe.Pointer(skC))
	ekC := C.CString(ek)
	defer C.free(unsafe.Pointer(ekC))
	rC := C.CString(r)
	defer C.free(unsafe.Pointer(rC))

	proofC := C.genProduceproof(idC, roleC, cmtAC, cmtUC, hencC, authC, pkC, skC, ekC, rC)

	proofGo := C.GoString(proofC)
	return proofGo
}

func VerifyProduceProof(id, role, cmtA, cmtU, henc, auth, proof string) error {
	defer timeCost("Verify Produce")()
	proofC := C.CString(proof)
	defer C.free(unsafe.Pointer(proofC))

	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	roleC := C.CString(role)
	defer C.free(unsafe.Pointer(roleC))
	cmtAC := C.CString(cmtA)
	defer C.free(unsafe.Pointer(cmtAC))
	cmtUC := C.CString(cmtU)
	defer C.free(unsafe.Pointer(cmtUC))
	hencC := C.CString(henc)
	defer C.free(unsafe.Pointer(hencC))
	authC := C.CString(auth)
	defer C.free(unsafe.Pointer(authC))

	tf := C.verifyProduceproof(proofC, idC, roleC, cmtAC, cmtUC, hencC, authC)
	if !tf {
		return errors.New("verifying produce proof failed")
	}
	return nil
}

func GenShareProof(idA, idB, cmtA, cmtU1, cmtU2, henc, auth, pkB, pkC, sk, ekA, ekB, rA, rB, roleA string) string {
	defer timeCost("Generate Share")()
	idAC := C.CString(idA)
	defer C.free(unsafe.Pointer(idAC))
	idBC := C.CString(idB)
	defer C.free(unsafe.Pointer(idBC))
	cmtAC := C.CString(cmtA)
	defer C.free(unsafe.Pointer(cmtAC))
	cmtU1C := C.CString(cmtU1)
	defer C.free(unsafe.Pointer(cmtU1C))
	cmtU2C := C.CString(cmtU2)
	defer C.free(unsafe.Pointer(cmtU2C))
	hencC := C.CString(henc)
	defer C.free(unsafe.Pointer(hencC))
	authC := C.CString(auth)
	defer C.free(unsafe.Pointer(authC))
	pkBC := C.CString(pkB)
	defer C.free(unsafe.Pointer(pkBC))
	pkCC := C.CString(pkC)
	defer C.free(unsafe.Pointer(pkCC))
	skC := C.CString(sk)
	defer C.free(unsafe.Pointer(skC))
	ekAC := C.CString(ekA)
	defer C.free(unsafe.Pointer(ekAC))
	ekBC := C.CString(ekB)
	defer C.free(unsafe.Pointer(ekBC))
	rAC := C.CString(rA)
	defer C.free(unsafe.Pointer(rAC))
	rBC := C.CString(rB)
	defer C.free(unsafe.Pointer(rBC))
	roleAC := C.CString(roleA)
	defer C.free(unsafe.Pointer(roleAC))
	proofC := C.genShareproof(idAC, idBC, cmtAC, cmtU1C, cmtU2C, hencC, authC, pkBC, pkCC, skC, ekAC, ekBC, rAC, rBC, roleAC)

	proofGo := C.GoString(proofC)
	return proofGo
}

func VerifyShareProof(idA, idB, cmtA, cmtU1, cmtU2, henc, auth, proof string) error {
	defer timeCost("Verify Share")()
	proofC := C.CString(proof)
	defer C.free(unsafe.Pointer(proofC))

	idAC := C.CString(idA)
	defer C.free(unsafe.Pointer(idAC))
	idBC := C.CString(idB)
	defer C.free(unsafe.Pointer(idBC))
	cmtAC := C.CString(cmtA)
	defer C.free(unsafe.Pointer(cmtAC))
	cmtU1C := C.CString(cmtU1)
	defer C.free(unsafe.Pointer(cmtU1C))
	cmtU2C := C.CString(cmtU2)
	defer C.free(unsafe.Pointer(cmtU2C))
	hencC := C.CString(henc)
	defer C.free(unsafe.Pointer(hencC))
	authC := C.CString(auth)
	defer C.free(unsafe.Pointer(authC))

	tf := C.verifyShareproof(proofC, idAC, idBC, cmtAC, cmtU1C, cmtU2C, hencC, authC)
	if !tf {
		return errors.New("verifying share proof failed")
	}
	return nil
}

func GenUpdateProof(id, cmtU1, cmtU2, henc, auth, pkB, pkD, sk, ek, r string) string {
	defer timeCost("Generate Update")()
	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	cmtU1C := C.CString(cmtU1)
	defer C.free(unsafe.Pointer(cmtU1C))
	cmtU2C := C.CString(cmtU2)
	defer C.free(unsafe.Pointer(cmtU2C))
	hencC := C.CString(henc)
	defer C.free(unsafe.Pointer(hencC))
	authC := C.CString(auth)
	defer C.free(unsafe.Pointer(authC))
	pkBC := C.CString(pkB)
	defer C.free(unsafe.Pointer(pkBC))
	pkDC := C.CString(pkD)
	defer C.free(unsafe.Pointer(pkDC))
	skC := C.CString(sk)
	defer C.free(unsafe.Pointer(skC))
	ekC := C.CString(ek)
	defer C.free(unsafe.Pointer(ekC))
	rC := C.CString(r)
	defer C.free(unsafe.Pointer(rC))

	proofC := C.genUpdateproof(idC, cmtU1C, cmtU2C, hencC, authC, pkBC, pkDC, skC, ekC, rC)

	proofGo := C.GoString(proofC)
	return proofGo
}

func VerifyUpdateProof(id, cmtU1, cmtU2, henc, auth, proof string) error {
	defer timeCost("Verify Update")()
	proofC := C.CString(proof)
	defer C.free(unsafe.Pointer(proofC))

	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	cmtU1C := C.CString(cmtU1)
	defer C.free(unsafe.Pointer(cmtU1C))
	cmtU2C := C.CString(cmtU2)
	defer C.free(unsafe.Pointer(cmtU2C))
	hencC := C.CString(henc)
	defer C.free(unsafe.Pointer(hencC))
	authC := C.CString(auth)
	defer C.free(unsafe.Pointer(authC))

	tf := C.verifyUpdateproof(proofC, idC, cmtU1C, cmtU2C, hencC, authC)
	if !tf {
		return errors.New("verifying update proof failed")
	}
	return nil
}

func GenAccessProof(id, cmtU, token, pk, ek, r, rt string) string {
	defer timeCost("Generate Access")()
	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	cmtUC := C.CString(cmtU)
	defer C.free(unsafe.Pointer(cmtUC))
	tokenC := C.CString(token)
	defer C.free(unsafe.Pointer(tokenC))
	pkC := C.CString(pk)
	defer C.free(unsafe.Pointer(pkC))
	ekC := C.CString(ek)
	defer C.free(unsafe.Pointer(ekC))
	rC := C.CString(r)
	defer C.free(unsafe.Pointer(rC))
	rtC := C.CString(rt)
	defer C.free(unsafe.Pointer(rtC))

	proofC := C.genAccessproof(idC, cmtUC, tokenC, pkC, ekC, rC, rtC)

	proofGo := C.GoString(proofC)
	return proofGo
}

func VerifyAccessProof(id, cmtU, token, proof string) error {
	defer timeCost("Verify Access")()
	proofC := C.CString(proof)
	defer C.free(unsafe.Pointer(proofC))

	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))
	cmtUC := C.CString(cmtU)
	defer C.free(unsafe.Pointer(cmtUC))
	tokenC := C.CString(token)
	defer C.free(unsafe.Pointer(tokenC))

	tf := C.verifyAccessproof(proofC, idC, cmtUC, tokenC)
	if !tf {
		return errors.New("verifying access proof failed")
	}
	return nil
}

// 计算医疗数据唯一标识,
func ComputeIDWithRawData(rawMedicalData map[string]string, r string) (string, map[string]string) {
	// hashList := make([]string, len(medicalDataJson))
	var hashList []string
	keyToHashMap := make(map[string]string, len(rawMedicalData))
	for k, v := range rawMedicalData {
		// fmt.Println(k + v)
		temp := sha256.Sum256([]byte(k + v))
		keyToHashMap[k] = hex.EncodeToString(temp[:])
		hashList = append(hashList, keyToHashMap[k])
		// fmt.Println(hashList[len(hashList)-1])
	}
	// 对hash值进行排序
	sort.Strings(hashList)
	// 最后加上随机字符串的哈希值
	hashList = append(hashList, ComputeCRH([]byte(r)))
	// 拼接所有哈希值
	var buffer bytes.Buffer
	for _, hash := range hashList {
		buffer.WriteString(hash)
	}
	id := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(id[:]), keyToHashMap
}

// 计算共享医疗数据的唯一标识
func ComputeShareIDWithRawDataAndIndex(dataID string, rawMedicalData map[string]string, index map[string]string,
	medicalDataR, r string) (string, []string, []int) {
	// 验证是否能够产生原始的医疗数据唯一标识
	id, keyToHashMap := ComputeIDWithRawData(rawMedicalData, medicalDataR)
	if id != dataID {
		log.Fatalln("raw medical data doesn't match the medical data id")
	}
	// 把hash转换成切片用以排序
	var hashList []string
	shareHashMap := make(map[string]string, len(index))
	// 这里不用考虑不同key对应同一个value，在key和value调换的过程中给会丢失数据的问题
	// 因为这里作为key'的是(key+value)的hash值，key本身不同，所以hash结果也不相同，都是一对一
	for k, v := range keyToHashMap {
		hashList = append(hashList, v)
		if _, ok := index[k]; ok {
			shareHashMap[v] = k
		}
	}
	// 对hash值进行排序
	sort.Strings(hashList)
	// 选出共享的数据hash，并记录其下标
	var shareHashList []string
	var shareHashIndex []int
	for i, hash := range hashList {
		if _, ok := shareHashMap[hash]; ok {
			shareHashList = append(shareHashList, hash)
			shareHashIndex = append(shareHashIndex, i)
		}
	}
	// 最后加上随机字符串的哈希值
	shareHashList = append(shareHashList, ComputeCRH([]byte(r)))
	var buffer bytes.Buffer
	for _, hash := range shareHashList {
		buffer.WriteString(hash)
	}
	shareID := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(shareID[:]), hashList, shareHashIndex
}

// 验证医疗数据的id和共享医疗数据的id是否正确
func CheckIDWithHashList(hashList []string, shareIndex []int, medicalDataID, shareMedicalDataID string) bool {
	if len(hashList) <= 2 || len(shareIndex) == 0 {
		log.Println("the length of hash list is le 2 or no share index data")
		return false
	}
	// 倒数第二个hash值为医疗数据的随机数hash值，最后一个hash值则为共享医疗数据的随机数hash值
	dataHashList := hashList[:len(hashList)-2]
	rHashList := hashList[len(hashList)-2:]

	// 对hash值进行排序，因为json规范中不保证数据有序
	sort.Strings(dataHashList)
	var sharedDataHashList []string
	dataHashLen := len(hashList) - 2
	for _, index := range shareIndex {
		if index >= dataHashLen {
			log.Println("the share index is invalid")
			return false
		}
		sharedDataHashList = append(sharedDataHashList, dataHashList[index])
	}

	// 验证医疗数据id
	dataHashList = append(dataHashList, rHashList[0])
	var buffer bytes.Buffer
	for _, hash := range dataHashList {
		buffer.WriteString(hash)
	}
	idByte := sha256.Sum256(buffer.Bytes())
	idHexStr := hex.EncodeToString(idByte[:])
	if idHexStr != medicalDataID {
		return false
	}
	// 验证共享医疗术据id
	buffer.Reset()
	sharedDataHashList = append(sharedDataHashList, rHashList[1])
	for _, hash := range sharedDataHashList {
		buffer.WriteString(hash)
	}
	idByte = sha256.Sum256(buffer.Bytes())
	idHexStr = hex.EncodeToString(idByte[:])
	return idHexStr == shareMedicalDataID
}

// 将对称密钥ek和随机数r组合
func LinkEkAndR(ek, r string) []byte {
	linkKey := LinkKey{
		Ek: ek,
		R:  r,
	}
	res, err := json.Marshal(linkKey)
	if err != nil {
		log.Fatalf("Marshal LinkKey err: %v", err)
	}
	return res
}

// 从客户端证书中解析出对外公布的公钥
func GetClientPublicKeyFromCert(userCa gateway.Identity) (string, error) {
	cert := userCa.(*gateway.X509Identity).Certificate()
	block, _ := pem.Decode([]byte(cert))
	certDecoded, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse cert from block err: %v", err)
	}
	fmt.Println("public key algorithm is: ", certDecoded.PublicKeyAlgorithm.String())
	publicKeyDer, err := x509.MarshalPKIXPublicKey(certDecoded.PublicKey)
	if err != nil {
		fmt.Println("marshal PKIXPublicKey err: ", err)
	}
	// 转换成十六机制字符串，对外公布
	patientPublicKeyStr := hex.EncodeToString(publicKeyDer)
	return patientPublicKeyStr, nil
}

// func main() {

// Produce Test
// ek := "2435ac"
// r := "23525"
// fmt.Println(string(LinkEkAndR(ek, r)))

// id := "123"
// role := "222"
// henc := "c3a"

// proof := "1d73fb6eb420d5232a8d37cde4c4e798d2ba9d358195da3574d9149fc8ac16d51fa4145cb99472b1f1f0afff70c4cdab673916d150abc3b6e36f81b7bc4c78102bb41acdfdfd2b908aa0a86cc3adb81e2bba4c52b7e11aa3b273527956bebe4e0e1742fea0e923cd5957d3475c2ef8093b1f85af977756720d8931fbf4dcbda11fe00925b3ea49dd8f610f32de70336dc3e9d0fcc58514b2aeab5450a12da38a1df26998282687d197d196a694070b4333e24f146c578d953a31b6b7b809502622c2dcbd5bbca14a8538ddfbb08933dc6b257827ce435afc1ff041ac2080ce060bbce4f1308c9c6f49c5b623ab5e33b4272baba6f440bc15c642c1b87e87de19"
// cmtA := "e1997aca22efc1a6aa7e0d07edd3b52d97acfb906cde1a41dca84666c6517c15"
// cmtU := "00f9a4639ead90f034c97b6b142da769d3c1fe9d4b35c8b03bac05a1a0e366cc"
// auth := "bef04783f73c5b5ccdf5f3142e44830c860dbe4fc2b7d4699c65a95100c28324"

// VerifyProduceProof(id, role, cmtA, cmtU, henc, auth, proof)

// id := "123"
// role := "222"

// pk := "1243"
// sk := "2513"
// r := "6767345"
// ek := ComputePRF(sk, r)
// fmt.Println("ek is:", ek)

// cmtA := GenCMTA(id, role, pk, ek, r)
// fmt.Println("cmtA is:", cmtA)

// cmtU := GenCMTU(id, pk, ek, r)
// fmt.Println("cmtU is:", cmtU)

// henc := "c3a"
// auth := ComputePRF(sk, henc)
// fmt.Println("auth is:", auth)

// proof := GenProduceProof(id, role, cmtA, cmtU, henc, auth, pk, sk, ek, r)
// if string(proof[0:10]) == "0000000000" {
// 	fmt.Println("can't generate proof")
// 	return
// }
// fmt.Println(proof)
// fmt.Println(string(proof))

// VerifyProduceProof(id, role, cmtA, cmtU, henc, auth, proof)

// ----------------------------------------------------

/*
	// Share Test
	idA := "12341"
	idB := "1ca52341"
	pkB := "634b2a"
	pkC := "876cbbabcdf"
	roleA := "497a89f8cd"
	ekA := "32465ca"
	rA := "3248371"
	rB := "7657cb87a8768d"

	sk := "86c868ab86d86"
	ekB := ComputePRF(sk, rB)

	cmtA := GenCMTA(idA, roleA, pkB, ekA, rA)

	cmtU1 := GenCMTU(idB, pkB, ekB, rB)
	cmtU2 := GenCMTU(idB, pkC, ekB, rB)

	henc := "c44198af"
	auth := ComputePRF(sk, henc)

	fmt.Println("idA is:", idA)
	fmt.Println("idB is:", idB)
	fmt.Println("cmtA is:", cmtA)
	fmt.Println("cmtU1 is:", cmtU1)
	fmt.Println("cmtU2 is:", cmtU2)
	fmt.Println("henc is:", henc)
	fmt.Println("auth is:", auth)

	proof := GenShareProof(idA, idB, cmtA, cmtU1, cmtU2, henc, auth, pkB, pkC, sk, ekA, ekB, rA, rB, roleA)
	if string(proof[0:10]) == "0000000000" {
		fmt.Println("can't generate proof")
		return
	}
	fmt.Println(string(proof))

	VerifyShareProof(idA, idB, cmtA, cmtU1, cmtU2, henc, auth, proof)

	// idA := "12341"
	// idB := "1ca52341"
	// cmtA := "0dbe7fdb5bc816aa5c0aa89949e07f6aae6390dcccf64ae278a899b688a6b4dd"
	// cmtU1 := "a0435792331259c0f6d9318c854cc7c4eb5a9864dbbb85f843685735140c7eee"
	// cmtU2 := "db03530a35237ad2b3abe02b7842097c3490172dd227b4546334fdb274ce2c2d"
	// henc := "c44198af"
	// auth := "7e27c0fef65c5a2147cd83c36e61bc0ba08fe3511fc8369578fb0c30762442b3"
	// proof := "194644fd15807d02f53174d4df458ac6ab2739ceb9b3b23194747a6eb32941100ace071aae87ed9bf298a27dddba07e49c9f7864f06fe6906224e5a4b2b94c4f016910b985413402a96477e041375d659b54f67968d5f806ee0e20c233ec4f580ed5bafa4516778ee5f1f1ff78fe25e4317f846c9a2ed92705cf9ef39ae4a4990f6ee6d2ed02763eab30d7f8ea69e54881a397940583b40d38fa3dd665eeeceb21600ba63a01de7d5069a0385d4f8c8ad39eca3949999a149bed453eb8627ab61cee356c01a42012786f65ff857efa1e5a8fba2346b9b13ab38ea3ba8fb88d8c1e29a80f8eb2a47f19645cacc660d1f5bc38c294894ad4d28c582b0e58ff3f47"

	// VerifyShareProof(idA, idB, cmtA, cmtU1, cmtU2, henc, auth, proof)
*/

// -----------------------------------------------

// update test
// id := "123"
// pkB := "1243"
// pkD := "222"
// sk := "2513"
// r := "6767345"
// ek := ComputePRF(sk, r)

// cmtU1 := GenCMTU(id, pkB, ek, r)

// cmtU2 := GenCMTU(id, pkD, ek, r)

// henc := "c3a"
// auth := ComputePRF(sk, henc)

// fmt.Println("cmtU1 is:", cmtU1)
// fmt.Println("cmtU2 is:", cmtU2)
// fmt.Println("henc is:", henc)
// fmt.Println("auth is:", auth)

// proof := GenUpdateProof(id, cmtU1, cmtU2, henc, auth, pkB, pkD, sk, ek, r)
// if string(proof[0:10]) == "0000000000" {
// 	fmt.Println("can't generate proof")
// 	return
// }
// fmt.Println(proof)
// fmt.Println(string(proof))

// VerifyUpdateProof(id, cmtU1, cmtU2, henc, auth, proof)

// id := "123"
// henc := "c3a"

// proof := "1994aebdaf0b3bb3e09f2f47cbe04ce672d44c8b1fc7e988eab70cf6300c1e5629e194cb6545d8bf2c18d352b52854a07049fbb3a3f8057440015dca7c4928ed0d63dc4a19132981af321a9a841a981e33875b21eb62f18733c2c8834dbadf3d2052189c1122db7343729dd423d9031ec6c01f4173fdca3c265636a39ec01edf0beafd1fa6f9e958288afb49ccfc1fc2f27599e303755c777ef79e35138dc86d2003feb7cfec6c6b9c29497b800d6919af5782bf887be7471d1cb8db6c300d251ad48f05461b6c94724e88761d821dab873ab13f1b71f36e3fe1307b6657f9a40e3fd131c1db91552a4348de6c14847e0df5c1924fa17dadbda91988f9898a73"
// cmtU1 := "199a0ba34eeecb896988559bd5b01555dc548354b8ce439e10137cef3260bb87"
// cmtU2 := "2cb150866c66415f44cf0bbb28e2abfff41ad3d3166260140c23c94404fd542b"
// auth := "dc341c53b4577e8f2edf722bc5d5c0e9980610a6140cf826af5c8a388468eeeb"

// VerifyUpdateProof(id, cmtU1, cmtU2, henc, auth, proof)

// id := "123"
// pk := "1243"
// r := "6767345"
// rt := "987ca998f988b0890cA"
// ek := "54578cb8788f8b28a"

// cmtU := GenCMTU(id, pk, ek, r)

// token := ComputePRF(pk, rt)

// fmt.Println("cmtU is:", cmtU)
// fmt.Println("token is:", token)

// proof := GenAccessProof(id, cmtU, token, pk, ek, r, rt)
// if string(proof[0:10]) == "0000000000" {
// 	fmt.Println("can't generate proof")
// 	return
// }
// fmt.Println(string(proof))

// VerifyAccessProof(id, cmtU, token, proof)

// 	id := "123"
// 	cmtU := "959b7df842744faf365ebc93595096b423053a683eb314c4a43a94623cf6a754"
// 	token := "ee6767563387d6845f610fd41b111b464e3e6ea1455cb7a0839ba4e3c479cb15"
// 	proof := "271301d0b4fb5699c38dfe69e5b158229c2a1a577066930c940bb7665bc039a02323c621cc84ed3541fb4f0a95a1799fffda255ea2c8da5170894a7894e82d121e8ae596dd7f4aa566f7ab0b52c8e059a729344117c425a469612feaf09b0b6822acfaa96837c39d3a0b1dd565103f0b6ee2d44fd5703fa02cda2dd8fac8ea7212f34faf738ffac9cf34f43f806dbda5b9ebe3adfb2e6b827d5cc8dc4e81bd7121ec9839afd96b3b261078309002d946b3ddcd2507e3ed238f63c24a74f888a71d284e2b14f3ba183e4b767d26e48ce1569cd90a9897265200513fcd481ca9231ee222a3aaebf5838dbc2f7cd45276d68d4c2ed3c524a3710605cad145a4425e"

// 	VerifyAccessProof(id, cmtU, token, proof)
// }
