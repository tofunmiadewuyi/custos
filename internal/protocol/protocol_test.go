package protocol

import (
	"bytes"
	"testing"
)

// The two signed message types must produce different signing inputs for the
// same host/seq/data, so a snapshot signature can never be replayed as a sets one.
func TestSigningInputDomainSeparation(t *testing.T) {
	host, seq, data := "host-1", uint64(7), []byte(`{"x":1}`)
	snap := SnapshotSigningInput(host, seq, data)
	sets := SecretSetsSigningInput(host, seq, data)
	if bytes.Equal(snap, sets) {
		t.Fatal("snapshot and sets signing inputs must differ")
	}
	if !bytes.Contains(snap, []byte(snapshotSigTag)) || !bytes.Contains(sets, []byte(setsSigTag)) {
		t.Fatal("each input must carry its own domain-separation tag")
	}
}
