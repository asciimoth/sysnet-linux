//go:build linux

// nolint
package connmark

import (
	"reflect"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func TestNormalizeMarks(t *testing.T) {
	got, err := normalizeMarks([]Mark{
		{Value: 0x100, Mask: 0xff00},
		{Value: 0x100, Mask: 0xff00},
		{Value: 0x200, Mask: 0xff00},
	})
	if err != nil {
		t.Fatalf("normalizeMarks() error = %v", err)
	}
	want := []Mark{
		{Value: 0x100, Mask: 0xff00},
		{Value: 0x200, Mask: 0xff00},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeMarks() = %#v, want %#v", got, want)
	}
}

func TestNormalizeMarksRejectsInvalidSelectors(t *testing.T) {
	tests := []struct {
		name  string
		marks []Mark
	}{
		{
			name:  "zero mask",
			marks: []Mark{{Value: 0x100}},
		},
		{
			name: "overlap",
			marks: []Mark{
				{Value: 0x100, Mask: 0xff00},
				{Value: 0x180, Mask: 0xff80},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeMarks(tt.marks); err == nil {
				t.Fatal("normalizeMarks() succeeded, want error")
			}
		})
	}
}

func TestSaveAndRestoreExpressions(t *testing.T) {
	mark := Mark{Value: 0xeb9f0001, Mask: 0xffffffff}

	save := saveMarkExprs(mark)
	if len(save) != 5 {
		t.Fatalf("saveMarkExprs len = %d, want 5", len(save))
	}
	if got, ok := save[0].(*expr.Meta); !ok ||
		got.Key != expr.MetaKeyMARK || got.Register != 1 || got.SourceRegister {
		t.Fatalf("save load expression = %#v, want meta mark load", save[0])
	}
	assertMarkCmp(t, save[1], save[2], mark)
	if got, ok := save[3].(*expr.Immediate); !ok ||
		!reflect.DeepEqual(
			got.Data,
			binaryutil.NativeEndian.PutUint32(mark.Value),
		) {
		t.Fatalf("save immediate = %#v, want mark value", save[3])
	}
	if got, ok := save[4].(*expr.Ct); !ok ||
		got.Key != expr.CtKeyMARK || got.Register != 1 || !got.SourceRegister {
		t.Fatalf("save set expression = %#v, want ct mark set", save[4])
	}

	restore := restoreMarkExprs(mark)
	if got, ok := restore[0].(*expr.Ct); !ok ||
		got.Key != expr.CtKeyMARK || got.Register != 1 || got.SourceRegister {
		t.Fatalf("restore load expression = %#v, want ct mark load", restore[0])
	}
	assertMarkCmp(t, restore[1], restore[2], mark)
	if got, ok := restore[4].(*expr.Meta); !ok ||
		got.Key != expr.MetaKeyMARK || got.Register != 1 || !got.SourceRegister {
		t.Fatalf("restore set expression = %#v, want meta mark set", restore[4])
	}
}

func assertMarkCmp(t *testing.T, bitwiseExpr, cmpExpr expr.Any, mark Mark) {
	t.Helper()
	bitwise, ok := bitwiseExpr.(*expr.Bitwise)
	if !ok {
		t.Fatalf("bitwise expression = %#v, want *expr.Bitwise", bitwiseExpr)
	}
	if bitwise.SourceRegister != 1 || bitwise.DestRegister != 1 ||
		bitwise.Len != 4 ||
		!reflect.DeepEqual(
			bitwise.Mask,
			binaryutil.NativeEndian.PutUint32(mark.Mask),
		) {
		t.Fatalf("bitwise expression = %#v, want mark mask", bitwise)
	}
	cmp, ok := cmpExpr.(*expr.Cmp)
	if !ok {
		t.Fatalf("cmp expression = %#v, want *expr.Cmp", cmpExpr)
	}
	if cmp.Op != expr.CmpOpEq || cmp.Register != 1 ||
		!reflect.DeepEqual(
			cmp.Data,
			binaryutil.NativeEndian.PutUint32(mark.Value&mark.Mask),
		) {
		t.Fatalf("cmp expression = %#v, want masked mark equality", cmp)
	}
}
