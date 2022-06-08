/**
 * @Time    :2022/6/6 14:42
 * @Author  :Xiaoyu.Zhang
 */

package pfx

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"os"
)

//参考文档：
//https://studygolang.com/articles/29971?fr=sidebar
//https://www.csdn.net/tags/MtTaEgzsMDg0MDA0LWJsb2cO0O0O.html

// GetPublicAndPrivateKeyFromPfx
/**
 *  @Description: 从PFX证书中解析公私钥
 *  @param pfxPath PFX证书
 *  @param privatePassword 密码
 *  @return privateKey 私钥
 *  @return publicKey 公钥
 *  @return err 错误
 */
func GetPublicAndPrivateKeyFromPfx(pfxPath, privatePassword string) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {
	// 打开文件
	f, err := os.Open(pfxPath)
	defer f.Close()
	if err != nil {
		return
	}
	// 读取文件
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}
	// 因为pfx证书公钥和密钥是成对的，所以要先转成pem.Block
	blocks, err := pkcs12.ToPEM(bytes, privatePassword)
	if err != nil {
		return
	}
	if len(blocks) != 2 {
		err = errors.New("解密错误")
		return
	}
	// 拿到第一个block，用x509解析出私钥（当然公钥也是可以的）
	privateKey, err = x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	if err != nil {
		return
	}
	// 解析公钥
	x509Cert, err := x509.ParseCertificate(blocks[1].Bytes)
	if err != nil {
		return
	}
	publicKey = x509Cert.PublicKey.(*rsa.PublicKey)
	return
}

// GetPublicKeyString
/**
 *  @Description: 获取Base64编码的公钥
 *  @param publicKey
 *  @return publicKeyString
 */
func GetPublicKeyString(publicKey *rsa.PublicKey) (publicKeyString string) {
	publicKeyByte := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyString = base64.StdEncoding.EncodeToString(publicKeyByte)
	return
}

// GetPrivateKeyString
/**
 *  @Description: 获取Base64编码的私钥
 *  @param privateKey
 *  @return privateKeyString
 */
func GetPrivateKeyString(privateKey *rsa.PrivateKey) (privateKeyString string) {
	privateKeyByte := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyString = base64.StdEncoding.EncodeToString(privateKeyByte)
	return
}
