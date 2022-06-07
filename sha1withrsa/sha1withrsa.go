/**
 * @Time    :2022/6/6 15:14
 * @Author  :Xiaoyu.Zhang
 */

package sha1withrsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

// Sign
/**
 *  @Description: sha1withrsa 签名
 *  @param privateKey 私钥
 *  @param content 需要签名的内容
 *  @return sign 签名
 *  @return err 错误
 */
func Sign(privateKey *rsa.PrivateKey, content string) (sign string, err error) {
	h := crypto.Hash.New(crypto.SHA1)
	h.Write([]byte(content))
	hashed := h.Sum(nil)
	var signature []byte
	signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed)
	if err != nil {
		return
	}
	sign = base64.StdEncoding.EncodeToString(signature)
	return
}

// RSAVerify
/**
 *  @Description: 验签
 *  @param publicKey 公钥
 *  @param originalData 原始数据
 *  @param ciphertext 签名
 *  @return ok 验签结果
 *  @return error 错误
 */
func RSAVerify(publicKey *rsa.PublicKey, originalData, ciphertext string) (ok bool, err error) {
	h := crypto.Hash.New(crypto.SHA1)
	h.Write([]byte(originalData))
	digest := h.Sum(nil)
	body, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest, body)
	if err != nil {
		return false, err
	}
	return true, nil
}
