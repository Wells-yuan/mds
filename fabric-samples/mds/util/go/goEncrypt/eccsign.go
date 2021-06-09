package goEncrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"runtime"
)

/*
@Time : 2018/11/4 18:51
@Author : wuman
@File : EccSign
@Software: GoLand
*/

type dsaSignature struct {
	R, S *big.Int
}

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile)
}

func EccSign(msg []byte, Key []byte) ([]byte, error) {
	block, _ := pem.Decode(Key)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	tempPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	// tempPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	// Convert to the private key in the ecies package in the ethereum package
	tempPrivateKey1 := tempPrivateKey.(*ecdsa.PrivateKey)
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, tempPrivateKey1, resultHash)
	if err != nil {
		return nil, err
	}

	// rText, err := r.MarshalText()
	// if err != nil {
	// 	return nil, err
	// }
	// sText, err := s.MarshalText()
	// if err != nil {
	// 	return nil, err
	// }

	signature := dsaSignature{
		R: r,
		S: s,
	}
	res, err := asn1.Marshal(signature)
	if err != nil {
		return nil, err
	}

	return res, nil

	// return rText,sText,nil
}

func EccVerifySign(msg []byte, Key []byte, rText, sText []byte) bool {
	block, _ := pem.Decode(Key)
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey := publicKeyInterface.(*ecdsa.PublicKey)
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}
