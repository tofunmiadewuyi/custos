package controlplane

import "testing"

func TestValidateEntries(t *testing.T) {
	cases := []struct {
		name    string
		entries []setEntryInput
		ok      bool
	}{
		{"empty set", nil, true},
		{"normal", []setEntryInput{{"DB_URL", "x"}, {"MASTER_KEY", "y"}}, true},
		{"empty key", []setEntryInput{{"", "y"}}, false},
		{"duplicate key", []setEntryInput{{"K", "1"}, {"K", "2"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateEntries(c.entries)
			if c.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
