package sm3

import (
	"bytes"
	"os"
	"testing"

	tjfocsm3 "github.com/jianlu8023/go-gmsm/tjfoc/gmsm/sm3"
)

// TestSm3 复刻原 tjfoc 测试流程（写 ifile 再读取摘要），并断言新实现
// （emmansun）与原 tjfoc 实现的摘要逐字节一致——等价性证据。
func TestSm3(t *testing.T) {
	msg := []byte("test")
	if err := os.WriteFile("ifile", msg, 0644); err != nil {
		t.Fatal(err)
	}
	msg, err := os.ReadFile("ifile")
	if err != nil {
		t.Fatal(err)
	}

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

	// 与原实现逐字节比对
	if old := tjfocsm3.Sm3Sum(msg); !bytes.Equal(sum, old) {
		t.Fatalf("new Sm3Sum = %x, tjfoc Sm3Sum = %x", sum, old)
	}
	oldHw := tjfocsm3.New()
	oldHw.Write(msg)
	if oldHash := oldHw.Sum(nil); !bytes.Equal(hash, oldHash) {
		t.Fatalf("new hash = %x, tjfoc hash = %x", hash, oldHash)
	}

	// 长消息（跨块）一致性
	long := bytes.Repeat([]byte("1234567890"), 1234)
	if old := tjfocsm3.Sm3Sum(long); !bytes.Equal(Sm3Sum(long), old) {
		t.Fatal("long message digest mismatch with tjfoc")
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
