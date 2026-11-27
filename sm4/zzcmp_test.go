package sm4

import (
	"fmt"
	"testing"

	tjfocsm4 "github.com/jianlu8023/go-gmsm/tjfoc/gmsm/sm4"
)

// TestCMP 新(sm4, emmansun)与旧(tjfoc)实现的四模式输出逐字节比对。
// 注意：两包各有独立的全局 IV 变量，此处分别设置，互不干扰。
func TestCMP(t *testing.T) {
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	iv := []byte("0000000000000000")
	SetIV(iv)
	tjfocsm4.SetIV(append([]byte(nil), iv...))

	for _, name := range []string{"Cbc", "Ecb", "CFB", "OFB"} {
		var ne, oe, nd, od []byte
		var err1, err2 error
		switch name {
		case "Cbc":
			ne, err1 = Sm4Cbc(key, data, true)
			oe, err2 = tjfocsm4.Sm4Cbc(key, data, true)
			nd, _ = Sm4Cbc(key, ne, false)
			od, _ = tjfocsm4.Sm4Cbc(key, oe, false)
		case "Ecb":
			ne, err1 = Sm4Ecb(key, data, true)
			oe, err2 = tjfocsm4.Sm4Ecb(key, data, true)
			nd, _ = Sm4Ecb(key, ne, false)
			od, _ = tjfocsm4.Sm4Ecb(key, oe, false)
		case "CFB":
			ne, err1 = Sm4CFB(key, data, true)
			oe, err2 = tjfocsm4.Sm4CFB(key, data, true)
			nd, _ = Sm4CFB(key, ne, false)
			od, _ = tjfocsm4.Sm4CFB(key, oe, false)
		case "OFB":
			ne, err1 = Sm4OFB(key, data, true)
			oe, err2 = tjfocsm4.Sm4OFB(key, data, true)
			nd, _ = Sm4OFB(key, ne, false)
			od, _ = tjfocsm4.Sm4OFB(key, oe, false)
		}
		if fmt.Sprintf("%x", ne) != fmt.Sprintf("%x", oe) {
			t.Errorf("%s: enc mismatch\n new=%x\n old=%x", name, ne, oe)
		}
		if err1 != nil || err2 != nil {
			t.Errorf("%s: err new=%v old=%v", name, err1, err2)
		}
		if fmt.Sprintf("%x", nd) != fmt.Sprintf("%x", od) {
			t.Errorf("%s: dec mismatch\n new=%x\n old=%x", name, nd, od)
		}
		if fmt.Sprintf("%x", nd) != fmt.Sprintf("%x", data) {
			t.Errorf("%s: roundtrip failed, dec=%x data=%x", name, nd, data)
		}
	}

	// GCM 互操作：新 Sm4GCM 加密 → 旧 Sm4GCM 解密（同一 IV/AAD）
	gkey := []byte("1234567890abcdef")
	giv := make([]byte, 16)
	gdata := []byte("0123456789abcdef")
	C, T, err := Sm4GCM(gkey, giv, gdata, []byte("12345678"), true)
	if err != nil {
		t.Fatalf("new Sm4GCM enc: %v", err)
	}
	C2, T2, err := tjfocsm4.Sm4GCM(gkey, giv, C, []byte("12345678"), false)
	if err != nil {
		t.Fatalf("old Sm4GCM dec: %v", err)
	}
	if fmt.Sprintf("%x", C2) != fmt.Sprintf("%x", gdata) || fmt.Sprintf("%x", T2) != fmt.Sprintf("%x", T) {
		t.Fatalf("GCM interop failed: ct=%x tag=%x", C2, T2)
	}
}
