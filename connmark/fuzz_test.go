//go:build linux

// nolint
package connmark

import (
	"encoding/binary"
	"testing"
)

func FuzzUntrustedInput(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 255, 255, 255, 255})
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		marks := make([]Mark, 0, min(len(input)/8, 64))
		for len(input) >= 8 && len(marks) < 64 {
			marks = append(marks, Mark{
				Value: binary.LittleEndian.Uint32(input[:4]),
				Mask:  binary.LittleEndian.Uint32(input[4:8]),
			})
			input = input[8:]
		}
		normalized, _ := normalizeMarks(marks)
		for _, mark := range normalized {
			_ = saveMarkExprs(mark)
			_ = restoreMarkExprs(mark)
			_ = matchMetaMarkExprs(mark)
			_ = matchCTMarkExprs(mark)
			_ = setCTMarkExprs(mark.Value)
			_ = setMetaMarkExprs(mark.Value)
			_ = immediateMark(mark.Value)
		}
		manager := newManagerWithConn(nil)
		_ = manager.Apply(Config{Marks: marks})
		_ = manager.Rollback()
		_ = manager.Close()
		_ = manager.Close()
	})
}
