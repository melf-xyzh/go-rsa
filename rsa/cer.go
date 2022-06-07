/**
 * @Time    :2022/6/7 15:33
 * @Author  :Xiaoyu.Zhang
 */

package myrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"time"
)

// 参考文档：https://blog.csdn.net/weixin_38299404/article/details/117341068
// 参考文档：https://blog.csdn.net/youngZ_H/article/details/123625301

// CreateCertificate
/**
 *  @Description: 生成自签证书文件(RSA)
 *  @param publicKey 公钥
 *  @param privateKey 私钥
 *  @param path 证书保存路径（不包含证书名）
 *  @return err 错误
 */
func CreateCertificate(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, caPath string) (err error) {
	// 创建证书模板
	//把 1 左移 128 位，返回给 big.Int
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	//返回在 [0, max) 区间均匀随机分布的一个随机值
	serialNumber, _ := rand.Int(rand.Reader, max)
	template := &x509.Certificate{
		// SerialNumber 是 CA 颁布的唯一序列号，在此使用一个大随机数来代表它
		SerialNumber: serialNumber,
		Subject: pkix.Name{ // 证书的主题信息
			Country:            []string{"CN"},      // 证书所属的国家
			Organization:       []string{"MELF"},    // 证书存放的公司名称
			OrganizationalUnit: []string{"Guide"},   // 证书所属的部门名称
			Province:           []string{"Shannxi"}, // 证书签发机构所在省
			CommonName:         "guide.melf.sapce",  // 证书域名
			Locality:           []string{"Xian"},    // 证书签发机构所在市
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, // 典型用法是指定叶子证书中的公钥的使用目的。它包括一系列的OID，每一个都指定一种用途。例如{id pkix 31}表示用于服务器端的TLS/SSL连接；{id pkix 34}表示密钥可以用于保护电子邮件。
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,                      // 指定了这份证书包含的公钥可以执行的密码操作，例如只能用于签名，但不能用来加密
		IsCA:                  true,                                                                       // 指示证书是不是ca证书
		BasicConstraintsValid: true,                                                                       // 指示证书是不是ca证书
	}
	// 创建证书,这里第二个参数和第三个参数相同则表示该证书为自签证书，返回值为DER编码的证书
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return errors.New("生成自签证书失败：" + err.Error())
	}
	// 将得到的证书放入pem.Block结构体中
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	}
	// 获取文件中的路径
	paths, _ := filepath.Split(caPath)
	// 创建文件夹
	err = os.MkdirAll(paths, os.ModePerm)
	if err != nil {
		return err
	}
	var file *os.File
	// 创建ca.crt（证书）文件
	file, err = os.Create(path.Join(caPath, "ca.crt"))
	defer file.Close()
	// 通过pem编码并写入磁盘文件
	err = pem.Encode(file, &block)
	if err != nil {
		return err
	}
	// 将私钥中的密钥对放入pem.Block结构体中
	block = pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	// 创建ca.key（私钥）文件
	file, err = os.Create(path.Join(caPath, "ca.key"))
	if err != nil {
		return
	}
	// 通过pem编码并写入磁盘文件
	err = pem.Encode(file, &block)
	if err != nil {
		return err
	}
	return
}

// LoadCertificate
/**
 *  @Description: 读取CA证书
 *  @param path CA证书路径
 *  @return certificate CA证书
 *  @return err 错误
 */
func LoadCertificate(path string) (certificate *x509.Certificate, err error) {
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
		err = errors.New("证书错误")
		return
	}
	certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	return
}
