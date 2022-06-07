/**
 * @Time    :2022/6/7 12:38
 * @Author  :Xiaoyu.Zhang
 */

package main

import (
	"crypto/rsa"
	"fmt"
	"github.com/melf-xyzh/go-rsa/pfx"
	"github.com/melf-xyzh/go-rsa/rsa"
	"github.com/melf-xyzh/go-rsa/sha1withrsa"
	"log"
)

func main() {
	content := "123456789"

	// 生成公钥和私钥
	privateKey, publicKey, err := myrsa.GenerateRsaKey(512)
	if err != nil {
		return
	}

	//myrsa.CreateZhenShu(publicKey, privateKey)
	sign, err := sha1withrsa.Sign(privateKey, content)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sign)
	verify, err := sha1withrsa.RSAVerify(publicKey, content, sign)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verify)

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

	privateKey, err = myrsa.ReadPrivatePem("cert/private.pem")
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err = myrsa.ReadPublicPem("cert/public.pem")
	if err != nil {
		log.Fatal(err)
	}

	sign, err = sha1withrsa.Sign(privateKey, content)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sign)
	verify, err = sha1withrsa.RSAVerify(publicKey, content, sign)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verify)

	// 生成私钥文件（ec格式）
	err = myrsa.CreatePrivateEC(privateKey, "cert/private.key")
	if err != nil {
		log.Fatal(err)
	}
	// 生成公钥文件（ec格式）
	err = myrsa.CreatePublicEC(publicKey, "cert/public.key")
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err = myrsa.ReadPrivateEC("cert/private.key")
	if err != nil {
		log.Fatal(err)
	}

	publicKey, err = myrsa.ReadPublicEC("cert/public.key")
	if err != nil {
		log.Fatal(err)
	}

	sign, err = sha1withrsa.Sign(privateKey, content)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sign)
	verify, err = sha1withrsa.RSAVerify(publicKey, content, sign)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verify)

	err = myrsa.CreateCertificate(publicKey, privateKey, "cert/ca/")
	if err != nil {
		log.Fatal(err)
	}

	certificate, err := myrsa.LoadCertificate("cert/ca/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	pfx.PrintPublicKey(	publicKey)
	publicKey = certificate.PublicKey.(*rsa.PublicKey)
	pfx.PrintPublicKey(	publicKey)

	// 加密
	encrypt, err := myrsa.RsaEncrypt(publicKey, content)
	if err != nil {
		return
	}
	fmt.Println(encrypt)
	// 解密
	data, err := myrsa.RsaDecrypt(privateKey,encrypt)
	if err != nil {
		return
	}
	fmt.Println(data)
}
