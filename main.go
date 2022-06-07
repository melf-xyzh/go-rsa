/**
 * @Time    :2022/6/7 12:38
 * @Author  :Xiaoyu.Zhang
 */

package main

import (
	"fmt"
	"github.com/melf-xyzh/go-rsa/rsa"
	"github.com/melf-xyzh/go-rsa/sha1withrsa"
	"log"
)

func main() {
	// 生成公钥和私钥
	privateKey, publicKey, err := myrsa.GenerateRsaKey(512)
	if err != nil {
		return
	}

	//myrsa.CreateZhenShu(publicKey, privateKey)

	err = myrsa.CreatePrivateEC(privateKey, "cert/private.key")
	if err != nil {
		log.Fatal(err)
	}

	// 生成公钥文件（pem格式）
	err = myrsa.CreatePrivatePem(privateKey, "")
	if err != nil {
		log.Fatal(err)
	}
	// 读取私钥文件（pem格式）
	err = myrsa.CreatePublicPem(publicKey, "")
	if err != nil {
		log.Fatal(err)
	}

	content := "dsailkjfldsjf;odskf;ods;"

	// 签名
	sign, err := sha1withrsa.Sign(privateKey, content)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sign)

	// 验签
	verify, err := sha1withrsa.RSAVerify(publicKey, content, sign)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verify)

	// 读取私钥文件（pem格式）
	privateKey, err = myrsa.ReadPrivatePem("cert/private.pem")
	if err != nil {
		log.Fatal(err)
	}

	// 读取公钥文件（pem格式）
	publicKey, err = myrsa.ReadPublicPem("cert/public.pem")
	if err != nil {
		log.Fatal(err)
	}

	sign, err = sha1withrsa.Sign(privateKey, "dsailkjfldsjf;odskf;ods;")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sign)
	verify, err = sha1withrsa.RSAVerify(publicKey, content, sign)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verify)

}
