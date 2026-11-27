package sm3

import (
	"hash"

	gmsm3 "github.com/emmansun/gmsm/sm3"
)

// New 返回一个 SM3 哈希实例，兼容原 github.com/jianlu8023/go-gmsm/sm3 的 API。
// 底层实现委托 github.com/emmansun/gmsm/sm3（汇编加速、常量时间）。
func New() hash.Hash {
	return gmsm3.New()
}

// Sm3Sum 一次性计算 data 的 SM3 摘要，保持原 API 返回 []byte。
func Sm3Sum(data []byte) []byte {
	sum := gmsm3.Sum(data)
	return sum[:]
}
