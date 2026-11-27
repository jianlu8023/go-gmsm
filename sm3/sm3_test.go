package sm3

import (
	"bytes"
	"testing"
)

// TestSm3 校验新实现（emmansun）自洽性：New/Sum 与 Sm3Sum 一致、长消息（跨块）正确。
// （与原 tjfoc 实现的逐字节等价性验证曾在迁移时通过，原始实现见 git 历史 0aacbe8）
func TestSm3(t *testing.T) {
	msg := []byte("test")

	hw := New()
	hw.Write(msg)
	hash := hw.Sum(nil)
	if len(hash) != 32 {
		t.Fatalf("hash length = %d, want 32", len(hash))
	}

	sum := Sm3Sum(msg)
	if !bytes.Equal(hash, sum) {
		t.Fatalf("New/Sum = %x, Sm3Sum = %x", hash, sum)
	}

	// 长消息（跨块）一致性
	long := bytes.Repeat([]byte("1234567890"), 1234)
	lh := New()
	lh.Write(long)
	if !bytes.Equal(lh.Sum(nil), Sm3Sum(long)) {
		t.Fatal("long message digest mismatch")
	}
}

func BenchmarkSm3(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	hw := New()
	for i := 0; i < t.N; i++ {
		hw.Sum(nil)
		Sm3Sum(msg)
	}
}
