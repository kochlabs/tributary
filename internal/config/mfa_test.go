package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nfa/internal/totp"
)

func TestMFA(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateUser(User{Username: "alice", Role: "admin"}, "Password-123"); err != nil {
		t.Fatal(err)
	}
	secret, err := db.BeginMFA("alice")
	if err != nil {
		t.Fatal(err)
	}
	if db.MFAEnabled("alice") {
		t.Fatal("enabled before confirming a code")
	}
	if _, err := db.EnableMFA("alice", "000000"); err != ErrBadCode {
		t.Fatalf("wrong code: %v", err)
	}
	code, _ := totp.Code(secret, totp.Step(time.Now()))
	codes, err := db.EnableMFA("alice", code)
	if err != nil || len(codes) != 10 || !db.MFAEnabled("alice") {
		t.Fatalf("enable: %v %v", codes, err)
	}
	// The enrolment code can't be reused to sign in.
	if _, err := db.VerifyMFA("alice", code); err != ErrBadCode {
		t.Fatalf("replay after enrolment: %v", err)
	}
	next, _ := totp.Code(secret, totp.Step(time.Now())+1)
	if used, err := db.VerifyMFA("alice", next); err != nil || used {
		t.Fatalf("next step: %v %v", used, err)
	}
	// A recovery code works once, in any case and with or without dashes.
	rc := strings.ToUpper(strings.ReplaceAll(codes[3], "-", ""))
	if used, err := db.VerifyMFA("alice", rc); err != nil || !used {
		t.Fatalf("recovery: %v %v", used, err)
	}
	if _, err := db.VerifyMFA("alice", codes[3]); err != ErrBadCode {
		t.Fatal("recovery code reused")
	}
	if db.RecoveryCodesLeft("alice") != 9 {
		t.Fatal("recovery count")
	}
	var raw string
	db.db.QueryRow("SELECT totp_secret || recovery FROM users WHERE username = 'alice'").Scan(&raw)
	if strings.Contains(raw, secret) || strings.Contains(raw, codes[0]) {
		t.Fatal("secret or recovery code stored in clear")
	}
	if us, _ := db.Users(); !us[0].MFA {
		t.Fatal("user list doesn't show MFA")
	}
	if _, err := db.BeginMFA("alice"); err == nil {
		t.Fatal("re-enrolment while enabled")
	}
	if err := db.DisableMFA("alice"); err != nil || db.MFAEnabled("alice") {
		t.Fatal("disable")
	}
}
