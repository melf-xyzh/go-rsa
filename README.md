## go-rsa

### 安装

```bash
go get github.com/melf-xyzh/go-rsa
```

### 使用方法

#### PFX证书

```go
// 从PFX证书中解析公私钥
privateKey, publicKey, err := pfx.GetPublicAndPrivateKeyFromPfx("zhengshu.pfx", "123456")
if err != nil {
	return
}
pfx.PrintPublicKey(publicKey)
pfx.PrintPrivateKey(privateKey)
```

#### sha1withrsa

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

### 生成读取公私钥文件（pem格式）

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

