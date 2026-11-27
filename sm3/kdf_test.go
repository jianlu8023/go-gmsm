package sm3

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

// TestKdf 测试向量取自 emmansun/gmsm/sm3 上游 TestKdf（GB/T 35276 KDF）。
func TestKdf(t *testing.T) {
	tests := []struct {
		z    []byte
		len  int
		want string
	}{
		{[]byte("emmansun"), 16, "708993ef1388a0ae4245a19bb6c02554"},
		{[]byte("emmansun"), 32, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd4"},
		{[]byte("emmansun"), 48, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"},
		{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 48, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f"},
		{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 121, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f263086"},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("kdf-case-%d", i+1), func(t *testing.T) {
			want, _ := hex.DecodeString(tt.want)
			if got := Kdf(tt.z, tt.len); !reflect.DeepEqual(got, want) {
				t.Errorf("Kdf(%x, len=%d) = %x, want %x", tt.z, tt.len, got, want)
			}
		})
	}
}
