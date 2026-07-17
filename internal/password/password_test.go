package password

import "testing"

func TestHashVerify(t *testing.T) {
	hash, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := Verify(hash, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}

	ok, err = Verify(hash, "wrong password")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password verified")
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := Hash("password")
	b, _ := Hash("password")
	if a == b {
		t.Fatal("two hashes of the same password should differ (random salt)")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2id$broken"} {
		if _, err := Verify(bad, "x"); err == nil {
			t.Errorf("expected error for malformed hash %q", bad)
		}
	}
}
