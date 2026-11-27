/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package sm2 提供 SM2 算法（签名/验签、加密/解密、密钥协商）实现。
//
// 本包保持原 github.com/jianlu8023/go-gmsm/sm2（tjfoc/gmsm 来源）的全部导出
// API 与输出格式不变，底层算法核心（P-256 曲线运算、ECDSA 核心、SM2 加解密）
// 委托给 github.com/emmansun/gmsm v0.29.8 实现（含汇编优化路径）；
// ZA 摘要、KDF、密钥协商按原实现逐位保留。
// 原实现代码归档于 tjfoc/gmsm/sm2。
package sm2

// reference to ecdsa
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	gmsm2 "github.com/emmansun/gmsm/sm2"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/jianlu8023/go-gmsm/sm3"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

	C1C3C2 = 0
	C1C2C3 = 1
)

// PublicKey 保持原类型形态（字段可直接访问），曲线委托 emmansun 实现。
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey 保持原类型形态，签名/解密委托 emmansun 实现。
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

// P256Sm2 返回 SM2 曲线（emmansun 实现，单例，Params 指针身份稳定）。
func P256Sm2() elliptic.Curve {
	return gmsm2.P256()
}

// ec 返回 emmansun 视角的公钥（*ecdsa.PublicKey）。
func (pub *PublicKey) ec() *ecdsa.PublicKey {
	curve := pub.Curve
	if curve == nil {
		curve = P256Sm2()
	}
	return &ecdsa.PublicKey{Curve: curve, X: pub.X, Y: pub.Y}
}

// ec 返回 emmansun 视角的私钥（*gmsm2.PrivateKey）。
func (priv *PrivateKey) ec() (*gmsm2.PrivateKey, error) {
	curve := priv.Curve
	if curve == nil {
		curve = P256Sm2()
	}
	ecPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: priv.X, Y: priv.Y},
		D:         priv.D,
	}
	return new(gmsm2.PrivateKey).FromECPrivateKey(ecPriv)
}

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s
//
// opts 为 *SM2SignerOption（NewSM2SignerOption 创建）时委托 emmansun 的
// GM 语义签名：forceGMSign=true 时 msg 视为原始消息（内部做 ZA+SM3，uid 取自
// opts，未指定用 default_uid）；forceGMSign=false 时 msg 视为已算好的摘要。
// 其余 opts 保持原 SM2 消息语义（uid 固定 default_uid）。
func (priv *PrivateKey) Sign(random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error) {
	if sm2Opts, ok := signer.(*SM2SignerOption); ok {
		d, err := priv.ec()
		if err != nil {
			return nil, err
		}
		return gmsm2.SignASN1(random, d, msg, toGmsmOpts(sm2Opts))
	}
	r, s, err := Sm2Sign(priv, msg, nil, random)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

func (pub *PublicKey) Verify(msg []byte, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return Sm2Verify(pub, msg, default_uid, r, s)
}

func (pub *PublicKey) Sm3Digest(msg, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = default_uid
	}

	za, err := ZA(pub, uid)
	if err != nil {
		return nil, err
	}

	e, err := msgHash(za, msg)
	if err != nil {
		return nil, err
	}

	return e.Bytes(), nil
}

// ****************************Encryption algorithm****************************//
func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

// **************************Key agreement algorithm**************************//
// KeyExchangeB 协商第二部，用户B调用， 返回共享密钥k
func KeyExchangeB(klen int, ida, idb []byte, priB *PrivateKey, pubA *PublicKey, rpri *PrivateKey, rpubA *PublicKey) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priB, pubA, rpri, rpubA, false)
}

// KeyExchangeA 协商第二部，用户A调用，返回共享密钥k
func KeyExchangeA(klen int, ida, idb []byte, priA *PrivateKey, pubB *PublicKey, rpri *PrivateKey, rpubB *PublicKey) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priA, pubB, rpri, rpubB, true)
}

//****************************************************************************//

// Sm2Sign 按 GB/T 32918.2 对 msg 做 SM2 签名（uid 为空时使用 default_uid），
// 摘要部分（ZA + SM3）为本地实现以保持与原实现逐位等价，ECDSA 核心委托 emmansun。
func Sm2Sign(priv *PrivateKey, msg, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	digest, err := priv.PublicKey.Sm3Digest(msg, uid)
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	if c == nil {
		c = P256Sm2()
	}
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	ecPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: c, X: priv.X, Y: priv.Y},
		D:         priv.D,
	}
	// emmansun legacy 函数：hash 语义签名（e 已为本地计算的摘要值）
	return gmsm2.Sign(random, ecPriv, e.Bytes())
}

// Sm2Verify 按 GB/T 32918.2 验证 msg 的 SM2 签名（uid 为空时使用 default_uid），
// 摘要部分为本地实现，ECDSA 核心委托 emmansun。
func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	if c == nil {
		c = P256Sm2()
	}
	N := c.Params().N
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = default_uid
	}
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}
	return gmsm2.Verify(pub.ec(), e.Bytes(), r, s)
}

/*
 * hash 语义验签：hash 为已计算好的摘要值（不做 ZA 预处理）。
 */
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	if c == nil {
		c = P256Sm2()
	}
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	return gmsm2.Verify(pub.ec(), hash, r, s)
}

/*
 * sm2密文结构如下:
 *  x
 *  y
 *  hash
 *  CipherText
 */
func Encrypt(pub *PublicKey, data []byte, random io.Reader, mode int) ([]byte, error) {
	// 空消息时返回 (nil, nil)：归档实现该路径因 kdf(0) 恒返回 ok=false 而无限循环
	//（未终止 bug），此处按 emmansun 行为返回空密文。
	if len(data) == 0 {
		return nil, nil
	}
	curve := pub.Curve
	if curve == nil {
		curve = P256Sm2()
	}
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("sm2: public key point is the infinity")
	}
	splice := gmsm2.C1C3C2
	if mode == C1C2C3 {
		splice = gmsm2.C1C2C3
	}
	return gmsm2.Encrypt(random, pub.ec(), data, gmsm2.NewPlainEncrypterOpts(gmsm2.MarshalUncompressed, splice))
}

func Decrypt(priv *PrivateKey, data []byte, mode int) ([]byte, error) {
	switch mode {
	case C1C3C2:
		data = data[1:]
	case C1C2C3:
		data = data[1:]
		c1 := make([]byte, 64)
		c2 := make([]byte, len(data)-96)
		c3 := make([]byte, 32)
		copy(c1, data[:64])             //x1,y1
		copy(c2, data[64:len(data)-32]) //密文
		copy(c3, data[len(data)-32:])   //hash
		c := []byte{}
		c = append(c, c1...)
		c = append(c, c3...)
		c = append(c, c2...)
		data = c
	default:
		data = data[1:]
	}
	gsm, err := priv.ec()
	if err != nil {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	plain, err := gmsm2.Decrypt(gsm, append([]byte{0x04}, data...))
	if err != nil {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	return plain, nil
}

// crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return Decrypt(priv, msg, C1C3C2)
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey 保留原实现随机数生成逻辑（40 字节随机数 mod (N-2)+1），
// 曲线运算委托 emmansun。
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

	return priv, nil
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

// msgHash 计算 SM2 消息摘要 e = SM3(za || msg)（本地实现，保持原行为）。
func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
// 本地实现，与归档的 tjfoc 实现逐位一致（曲线参数取 P256Sm2().Params()，
// a = P - 3，SM2 曲线参数 .Bytes() 均为 32 字节，与 emmansun CalculateZA 等价）。
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}
	Entla := uint16(8 * uidLen)
	za.Write([]byte{byte((Entla >> 8) & 0xFF)})
	za.Write([]byte{byte(Entla & 0xFF)})
	if uidLen > 0 {
		za.Write(uid)
	}
	params := P256Sm2().Params()
	// SM2 曲线 a = p - 3，与归档实现 sm2P256.a 的取值一致
	a := new(big.Int).Sub(params.P, three)
	za.Write(a.Bytes())
	za.Write(params.B.Bytes())
	za.Write(params.Gx.Bytes())
	za.Write(params.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		yBuf = append(zeroByteSlice()[:32-n], yBuf...)
	}
	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

var three = new(big.Int).SetInt64(3)

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}
