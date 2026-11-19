package audit

import (
	"context"
	"testing"

	"github.com/dertown/network-control-centre/internal/store"
)

func TestChainDetectsTampering(t *testing.T) {
	st, _ := store.OpenPath(":memory:")
	l := New(st.DB)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l.Record(ctx, "derek", "dns.apply", "dns/pdns/home.lan.", map[string]int{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	if bad, _ := l.Verify(ctx); bad != 0 {
		t.Fatalf("fresh chain broken at %d", bad)
	}
	_, _ = st.DB.Exec(`UPDATE audit_log SET actor = 'mallory' WHERE id = 2`)
	if bad, _ := l.Verify(ctx); bad != 2 {
		t.Fatalf("tampering not detected, got %d", bad)
	}
}
