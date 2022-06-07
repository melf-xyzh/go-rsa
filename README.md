## go-rsa

### 安装

```bash
go get github.com/melf-xyzh/go-rsa
```

### 使用方法

### sha1withrsa

##### 签名

```go
// 需要签名的文本
context := "helloworld" 
// 签名
sign, err := sha1withrsa.Sign(privateKey, context)
if err != nil {
	log.Fatalln(err)
}
fmt.Println(sign)
```

##### 验签

```go
// 验签
verify, err := sha1withrsa.RSAVerify(publicKey, context, sign)
if err != nil {
	return
}
fmt.Println(verify)
```

### 加密 / 解密

```go
// 加密
encrypt, err := myrsa.RsaEncrypt(publicKey, content)
if err != nil {
	return
}
// 解密
data, err := myrsa.RsaDecrypt(privateKey,encrypt)
if err != nil {
	return
}
```

### 生成读取公私钥文件（pem格式 / PKCS1）

```go
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
```

### 生成读取公私钥文件（ec格式 / PKCS8）

```go
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
// 读取私钥文件（ec格式）
privateKey, err = myrsa.ReadPrivateEC("cert/private.key")
if err != nil {
	log.Fatal(err)
}
// 读取公钥文件（ec格式）
publicKey, err = myrsa.ReadPublicEC("cert/public.key")
if err != nil {
	log.Fatal(err)
}
```

### 生成证书文件（CA）

```go
// 生成CA证书
err = myrsa.CreateCertificate(publicKey, privateKey, "cert/ca/")
if err != nil {
	log.Fatal(err)
}
// 导入CA证书
certificate, err := myrsa.LoadCertificate("cert/ca/ca.crt")
if err != nil {
    log.Fatal(err)
}
```

### PFX证书

```go
// 从PFX证书中解析公私钥
privateKey, publicKey, err := pfx.GetPublicAndPrivateKeyFromPfx("zhengshu.pfx", "123456")
if err != nil {
	return
}
pfx.PrintPublicKey(publicKey)
pfx.PrintPrivateKey(privateKey)
```



