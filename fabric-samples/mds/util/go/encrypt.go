package util

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"hyperledger/fabric-samples/mds/util/go/goEncrypt"
	"math/big"
)

const (
	publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh4WJxxuxkrk1n5KMgV6XVZB3Kikd
iafFdLLbAgRG2Gmx4PVp1B80LyC6SMbuOBX5k0Dl5UWNYb+8Rjkt9tjzUA==
-----END PUBLIC KEY-----`
	privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7oI13ls6MwTcN8fK
QyyYFZ04Rf+DTvSKJ8NrpYrQo1qhRANCAASHhYnHG7GSuTWfkoyBXpdVkHcqKR2J
p8V0stsCBEbYabHg9WnUHzQvILpIxu44FfmTQOXlRY1hv7xGOS322PNQ
-----END PRIVATE KEY-----`

// 	privateKey = `-----BEGIN WUMAN ECC PRIVATE KEY-----
// MHcCAQEEIKozbXD9G6bGPJ26cCAfEdLrqAe697F8SiLRMdqxzNQ5oAoGCCqGSM49
// AwEHoUQDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1vFooGpsKCbLvrdUW4peVIwKEW
// +yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
// -----END WUMAN ECC PRIVATE KEY-----`

// 	publicKey = `-----BEGIN WUMAN ECC PUBLIC KEY-----
// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1v
// FooGpsKCbLvrdUW4peVIwKEW+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
// -----END WUMAN ECC PUBLIC KEY-----`
)

type dsaSignature struct {
	R, S *big.Int
}

func main() {
	plainText := []byte("窗前明月光，疑是地上霜,ECC加密解密")

	// 这里传入的私钥和公钥是要用GetECCKey里面得到的私钥和公钥，如果自己封装的话，
	// 获取密钥时传入的第一个参数是要用这条曲线elliptic.P256()，如果用别的会报无效公钥错误，
	// 例如用P521()这条曲线
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)

	cryptText, _ := goEncrypt.EccEncrypt(plainText, publicKey)
	fmt.Println("ECC传入公钥加密的密文为：", hex.EncodeToString(cryptText))

	msg, err := goEncrypt.EccDecrypt(cryptText, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("ECC传入私钥解密后的明文为：", string(msg))

	r := big.NewInt(3945798459240285763)
	s := big.NewInt(853048503453405032)
	a := dsaSignature{
		R: r,
		S: s,
	}
	res, err := asn1.Marshal(a)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(res)
	var demo dsaSignature
	_, err = asn1.Unmarshal(res, &demo)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(demo)

	res, err = goEncrypt.EccSign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(res)
}
