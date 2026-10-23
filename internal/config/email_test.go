package config

import "testing"

func TestEmailConfig(t *testing.T) {
	db := openTestDB(t)
	if e := db.Email(); e.Port != 587 || e.Security != "starttls" || e.Enabled {
		t.Fatalf("default %+v", e)
	}
	for _, bad := range []Email{
		{Enabled: true, From: "nfa@example.com"},                                             // no host
		{Host: "smtp.example.com:587", From: "nfa@example.com"},                              // port in host
		{Host: "smtp.example.com", From: "not an address"},                                   // bad sender
		{Host: "smtp.example.com", From: "nfa@example.com", Port: 70000},                     // bad port
		{Host: "smtp.example.com", From: "nfa@example.com", Security: "ssl"},                 // unknown security
		{Host: "smtp.example.com", From: "nfa@example.com", Security: "none", Username: "u"}, // password in the clear
		{Enabled: true, Host: "smtp.example.com", From: "nfa@example.com", Username: "u"},    // no password
	} {
		if _, err := db.SaveEmail(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	e, err := db.SaveEmail(Email{Enabled: true, Host: "smtp.example.com", Security: "tls", Username: "u", Password: "secret", From: "Tributary <nfa@example.com>"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Password != "" || !e.HasPassword || e.Port != 465 {
		t.Fatalf("saved %+v", e)
	}
	if s := db.storedEmail(); s.Password == "secret" || s.Password == "" {
		t.Fatalf("password stored as %q", s.Password)
	}
	// An empty password keeps the stored one.
	e.Password = ""
	if _, err := db.SaveEmail(e); err != nil {
		t.Fatal(err)
	}
	if s, _ := db.EmailSecrets(); s.Password != "secret" {
		t.Fatalf("kept %q", s.Password)
	}
	// The form's test send gets the stored password, unless the account changed.
	form := Email{Host: "smtp.example.com", Username: "u"}
	_ = db.FillEmailSecrets(&form)
	other := Email{Host: "smtp.example.com", Username: "someone-else"}
	_ = db.FillEmailSecrets(&other)
	if form.Password != "secret" || other.Password != "" {
		t.Fatalf("filled %q and %q", form.Password, other.Password)
	}
	// A different account with no password is refused; no username drops it.
	if _, err := db.SaveEmail(Email{Enabled: true, Host: "smtp.example.com", Username: "someone-else", From: "nfa@example.com"}); err == nil {
		t.Fatal("kept the old account's password for a new account")
	}
	if _, err := db.SaveEmail(Email{Enabled: true, Host: "smtp.example.com", Security: "none", From: "nfa@example.com"}); err != nil {
		t.Fatal(err)
	}
	if s := db.storedEmail(); s.Password != "" || s.Port != 25 {
		t.Fatalf("relay %+v", s)
	}
}
