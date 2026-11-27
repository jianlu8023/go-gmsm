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

sm4 acceleration
modified by Jack, 2017 Oct
*/

package sm4

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"strconv"

	gmsm4 "github.com/emmansun/gmsm/sm4"
)

const BlockSize = 16

var IV = make([]byte, BlockSize)

type SM4Key []byte

// Cipher is an instance of SM4 encryption.
// 底层块密码委托 github.com/emmansun/gmsm/sm4（汇编加速、常量时间），
// 本类型保留与原实现一致的结构与 API，模式函数（CBC/ECB/CFB/OFB）行为与原版逐位一致。
type Sm4Cipher struct {
	subkeys []uint32
	block1  []uint32
	block2  []byte
	block   cipher.Block
}

// NewCipher returns a Block that encrypts and decrypts using SM4.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	block, err := gmsm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Sm4Cipher{
		subkeys: nil,
		block1:  make([]uint32, 4),
		block2:  make([]byte, BlockSize),
		block:   block,
	}, nil
}

func (c *Sm4Cipher) BlockSize() int {
	return BlockSize
}

func (c *Sm4Cipher) Encrypt(dst, src []byte) {
	c.block.Encrypt(dst, src)
}

func (c *Sm4Cipher) Decrypt(dst, src []byte) {
	c.block.Decrypt(dst, src)
}

func xor(in, iv []byte) (out []byte) {
	if len(in) != len(iv) {
		return nil
	}
	out = make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = in[i] ^ iv[i]
	}
	return
}

func pkcs7Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("Invalid pkcs7 padding (len(padtext) == 0)")
	}
	unpadding := int(src[length-1])
	if unpadding > BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)")
	}
	for i := 0; i < unpadding; i++ {
		if src[length-1-i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

// SetIV sets the IV for the cipher.
// 注意：与原版一致，直接替换全局 IV 变量本身（而非拷贝内容），且 len 校验为静默失败（返回 error 但调用方可忽略）。
func SetIV(iv []byte) error {
	if len(iv) != BlockSize {
		return errors.New("SM4: invalid iv size")
	}
	IV = iv
	return nil
}

// Sm4Cbc CBC mode using SM4, with PKCS7 padding when encrypting.
// mode true=encrypt, false=decrypt.
func Sm4Cbc(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}
	iv := make([]byte, BlockSize)
	copy(iv, IV)
	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if mode {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := xor(inData[i*16:i*16+16], iv)
			out_tmp := make([]byte, 16)
			c.Encrypt(out_tmp, in_tmp)
			copy(out[i*16:i*16+16], out_tmp)
			iv = out_tmp
		}
	} else {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := inData[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			c.Decrypt(out_tmp, in_tmp)
			out_tmp = xor(out_tmp, iv)
			copy(out[i*16:i*16+16], out_tmp)
			iv = in_tmp
		}
		out, _ = pkcs7UnPadding(out)
	}

	return out, nil
}

// Sm4Ecb ECB mode using SM4, with PKCS7 padding when encrypting.
// mode true=encrypt, false=decrypt.
func Sm4Ecb(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}
	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	if mode {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := inData[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			c.Encrypt(out_tmp, in_tmp)
			copy(out[i*16:i*16+16], out_tmp)
		}
	} else {
		for i := 0; i < len(inData)/16; i++ {
			in_tmp := inData[i*16 : i*16+16]
			out_tmp := make([]byte, 16)
			c.Decrypt(out_tmp, in_tmp)
			copy(out[i*16:i*16+16], out_tmp)
		}
		out, _ = pkcs7UnPadding(out)
	}

	return out, nil
}

// 密码反馈模式（Cipher FeedBack (CFB)）
// https://blog.csdn.net/zy_strive_2012/article/details/102520356
// https://blog.csdn.net/sinat_23338865/article/details/72869841
func Sm4CFB(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}

	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	K := make([]byte, BlockSize)
	cipherBlock := make([]byte, BlockSize)
	plainBlock := make([]byte, BlockSize)
	if mode { //加密
		for i := 0; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, IV)
				cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
				copy(out[i*16:i*16+16], cipherBlock)
				continue
			}
			c.Encrypt(K, cipherBlock)
			cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
			copy(out[i*16:i*16+16], cipherBlock)
		}

	} else { //解密
		var i int = 0
		for ; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, IV)                                      //这里是加密，而不是调用解密方法Decrypt
				plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16]) //获取明文分组
				copy(out[i*16:i*16+16], plainBlock)
				continue
			}
			c.Encrypt(K, inData[(i-1)*16:(i-1)*16+16])
			plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16]) //获取明文分组
			copy(out[i*16:i*16+16], plainBlock)

		}

		out, _ = pkcs7UnPadding(out)
	}

	return out, nil
}

// 输出反馈模式（Output feedback, OFB）
// https://blog.csdn.net/chengqiuming/article/details/82390910
// https://blog.csdn.net/sinat_23338865/article/details/72869841
func Sm4OFB(key []byte, in []byte, mode bool) (out []byte, err error) {
	if len(key) != BlockSize {
		return nil, errors.New("SM4: invalid key size " + strconv.Itoa(len(key)))
	}
	var inData []byte
	if mode {
		inData = pkcs7Padding(in)
	} else {
		inData = in
	}

	out = make([]byte, len(inData))
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}

	K := make([]byte, BlockSize)
	cipherBlock := make([]byte, BlockSize)
	plainBlock := make([]byte, BlockSize)
	shiftIV := make([]byte, BlockSize)
	if mode { //加密
		for i := 0; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, IV)
				cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
				copy(out[i*16:i*16+16], cipherBlock)
				copy(shiftIV, K[:BlockSize])
				continue
			}
			c.Encrypt(K, shiftIV)
			cipherBlock = xor(K[:BlockSize], inData[i*16:i*16+16])
			copy(out[i*16:i*16+16], cipherBlock)
			copy(shiftIV, K[:BlockSize])
		}

	} else { //解密
		for i := 0; i < len(inData)/16; i++ {
			if i == 0 {
				c.Encrypt(K, IV)                                      //这里是加密，而不是调用解密方法Decrypt
				plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16]) //获取明文分组
				copy(out[i*16:i*16+16], plainBlock)
				copy(shiftIV, K[:BlockSize])
				continue
			}
			c.Encrypt(K, shiftIV)
			plainBlock = xor(K[:BlockSize], inData[i*16:i*16+16]) //获取明文分组
			copy(out[i*16:i*16+16], plainBlock)
			copy(shiftIV, K[:BlockSize])
		}
		out, _ = pkcs7UnPadding(out)
	}

	return out, nil
}
