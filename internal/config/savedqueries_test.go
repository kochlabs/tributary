package config

import (
	"errors"
	"testing"
)

func TestSavedQueries(t *testing.T) {
	db := openTestDB(t)
	db.CreateUser(User{Username: "root", Role: "admin"}, "Password-123x")
	for _, u := range []string{"ann", "bob"} {
		if err := db.CreateUser(User{Username: u, Role: "viewer"}, "Password-123x"); err != nil {
			t.Fatal(err)
		}
	}
	mine, err := db.SaveSavedQuery(SavedQuery{Name: "SSH", Query: "dst_port:22", Owner: "ann"})
	if err != nil || mine.ID == 0 || mine.Shared {
		t.Fatalf("%+v %v", mine, err)
	}
	if _, err := db.SaveSavedQuery(SavedQuery{Name: "SSH", Query: "x:1", Owner: "ann"}); !errors.Is(err, ErrSavedQueryExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := db.SaveSavedQuery(SavedQuery{Name: "SSH", Query: "dst_port:22", Owner: "bob"}); err != nil {
		t.Fatalf("names are per owner: %v", err)
	}
	shared, _ := db.SaveSavedQuery(SavedQuery{Name: "Threats", Query: "threat:*", Owner: "bob", Shared: true})
	// ann sees hers and bob's shared one, hers first; not bob's private one.
	list, _ := db.SavedQueries("ann")
	if len(list) != 2 || list[0].ID != mine.ID || list[1].ID != shared.ID {
		t.Fatalf("ann sees %+v", list)
	}
	// Updating keeps the owner.
	mine.Shared, mine.Owner = true, "bob"
	upd, err := db.SaveSavedQuery(mine)
	if err != nil || !upd.Shared || upd.Owner != "ann" {
		t.Fatalf("update: %+v %v", upd, err)
	}
	// A deleted user's queries go with them.
	if err := db.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	if list, _ := db.SavedQueries("ann"); len(list) != 1 {
		t.Fatalf("after deleting bob: %+v", list)
	}
}
