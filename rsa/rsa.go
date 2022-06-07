/**
 * @Time    :2022/6/6 15:37
 * @Author  :Xiaoyu.Zhang
 */

package myrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// GenerateRsaKey
/**
 *  @Description: 生成RSA公私钥
 *  @param keySize
 *  @return privateKey
 *  @return publicKey
 *  @return err
 */
func GenerateRsaKey(keySize int) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return
	}
	pubKey := privateKey.PublicKey
	publicKey = &pubKey
	return
}

// 参考文档：https://blog.csdn.net/lady_killer9/article/details/118026802

// CreatePrivatePem
/**
 *  @Description: 创建PEM格式私钥文件
 *  @param privateKey 私钥
 *  @param path 私钥文件保存路径
 *  @return err 错误
 */
func CreatePrivatePem(privateKey *rsa.PrivateKey, path string) (err error) {
	// 将私钥编码为pkcs1格式
	derText := x509.MarshalPKCS1PrivateKey(privateKey)
	// 使用pem.Block转为Block
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derText,
	}
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/private.pem"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	// 使用pem.Encode写入文件
	err = pem.Encode(file, block)
	if err != nil {
		return
	}
	return
}

// CreatePublicPem
/**
 *  @Description: 创建PEM格式公钥文件
 *  @param publicKey 公钥
 *  @param path 私钥文件保存路径
 *  @return err 错误
 */
func CreatePublicPem(publicKey *rsa.PublicKey, path string) (err error) {
	// 序列化公钥
	derStream := x509.MarshalPKCS1PublicKey(publicKey)
	// 使用pem.Block转为Block
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derStream,
	}
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/public.pem"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	// 使用pem.Encode写入文件
	err = pem.Encode(file, block)
	if err != nil {
		return
	}
	return
}

// ReadPrivatePem
/**
 *  @Description: 读取PEM格式私钥
 *  @param path 私钥文件保存路径
 *  @return privateKey 私钥
 *  @return err 错误
 */
func ReadPrivatePem(path string) (privateKey *rsa.PrivateKey, err error) {
	// 打开文件读取私钥
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fileInfo os.FileInfo
	fileInfo, err = file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	// 使用pem.Decode读取内容
	block, _ := pem.Decode(buf)
	if block == nil {
		err = errors.New("私钥错误")
		return
	}
	// 将pem格式私钥文件进行反序列化
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		err = errors.New("私钥错误：" + err.Error())
		return
	}
	return
}

// 参考文档：https://ask.csdn.net/questions/1012311

// ReadPublicPem
/**
 *  @Description: 读取PEM格式公钥
 *  @param path 公钥文件保存路径
 *  @return publicKey 公钥
 *  @return err 错误
 */
func ReadPublicPem(path string) (publicKey *rsa.PublicKey, err error) {
	// 打开文件读取私钥
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fileInfo os.FileInfo
	fileInfo, err = file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	// 使用pem.Decode读取内容
	block, _ := pem.Decode(buf)
	if block == nil {
		err = errors.New("公钥错误")
		return
	}
	// 将pem格式公钥文件进行反序列化
	publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		err = errors.New("公钥错误：" + err.Error())
		return
	}
	return
}

// CreatePrivateEC
/**
 *  @Description: 创建EC格式私钥文件
 *  @param privateKey 私钥
 *  @param path 私钥文件保存路径
 *  @return err 错误
 */
func CreatePrivateEC(privateKey *rsa.PrivateKey, path string) (err error) {
	// 将私钥编码为pkcs8格式
	derText, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}
	// 使用pem.Block转为Block
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derText,
	}
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/private.key"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	// 将私钥转为pem格式
	if err = pem.Encode(file, block); err != nil {
		panic(err)
	}
	file.Close()
	return
}

// CreatePublicEC
/**
 *  @Description: 创建EC格式公钥文件
 *  @param privateKey 公钥
 *  @param path 公钥文件保存路径
 *  @return err 错误
 */
func CreatePublicEC(publicKey *rsa.PublicKey, path string) (err error) {
	// 将私钥编码为pkcs8格式
	derText, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	// 使用pem.Block转为Block
	block := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: derText,
	}
	// 将私钥写入磁盘
	if path == "" {
		path = "cert/public.key"
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(path)
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	file, err = os.Create(path)
	// 将私钥转为pem格式
	if err = pem.Encode(file, block); err != nil {
		panic(err)
	}
	defer file.Close()
	return
}

// ReadPrivateEC
/**
 *  @Description: 读取EC格式私钥
 *  @param path 私钥文件保存路径
 *  @return privateKey 私钥
 *  @return err 错误
 */
func ReadPrivateEC(path string) (privateKey *rsa.PrivateKey, err error) {
	// 打开文件读取私钥
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fileInfo os.FileInfo
	fileInfo, err = file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	// 使用pem.Decode读取内容
	block, _ := pem.Decode(buf)
	if block == nil {
		err = errors.New("私钥错误")
		return
	}
	// 将pem格式私钥文件进行反序列化
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		err = errors.New("私钥错误：" + err.Error())
		return
	}
	return private.(*rsa.PrivateKey), nil
}

// ReadPublicEC
/**
 *  @Description: 读取EC格式公钥
 *  @param path 公钥文件保存路径
 *  @return privateKey 私钥
 *  @return err 错误
 */
func ReadPublicEC(path string) (publicKey *rsa.PublicKey, err error) {
	// 打开文件读取私钥
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var fileInfo os.FileInfo
	fileInfo, err = file.Stat()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, fileInfo.Size(), fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}
	// 使用pem.Decode读取内容
	block, _ := pem.Decode(buf)
	if block == nil {
		err = errors.New("公钥错误")
		return
	}
	// 将pem格式公钥文件进行反序列化
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err = errors.New("公钥错误：" + err.Error())
		return
	}
	return public.(*rsa.PublicKey), nil
}

// 参考文档：https://blog.csdn.net/lady_killer9/article/details/118026802

// RsaEncrypt
/**
 *  @Description: RSA加密
 *  @param publicKey 公钥
 *  @param data 需要解密的内容
 *  @return cipherText 加密后的内容
 *  @return error 错误
 */
func RsaEncrypt(publicKey *rsa.PublicKey, data string) (cipherText string, err error) {
	// 将内容转换为[]byte
	dateByte := []byte(data)
	// 加密
	cipherByte, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, dateByte)
	if err != nil {
		return
	}
	// 将其装换为16进制字符串
	cipherText = hex.EncodeToString(cipherByte)
	return cipherText, nil
}

// RsaDecrypt
/**
 *  @Description: RSA解密
 *  @param privateKey 私钥
 *  @param cipherText 加密后的字符串
 *  @return data 解密后的内容
 *  @return err 错误
 */
func RsaDecrypt(privateKey *rsa.PrivateKey, cipherText string) (data string, err error) {
	// 将加密的16进制字符串装换为[]byte
	cipherByte, err := hex.DecodeString(cipherText)
	if err != nil {
		return
	}
	// 解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherByte)
	if err != nil {
		return
	}
	data = string(plainText)
	return data, nil
}
