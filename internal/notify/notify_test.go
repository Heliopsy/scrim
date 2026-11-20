// SPDX-License-Identifier: AGPL-3.0-only

package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/heliopsy/scrim/internal/notify"
)

func TestMulti(t *testing.T) {
	ok := &notify.Recorder{NotifierName: "ntfy"}
	bad := &notify.Recorder{NotifierName: "telegram", Fail: errors.New("down")}
	req := notify.Request{ApprovalID: "ap1", Reason: "push"}
	if err := (notify.Multi{ok, bad}).Notify(context.Background(), req); err != nil {
		t.Fatalf("one working notifier must be enough: %v", err)
	}
	if len(ok.Sent()) != 1 || ok.Sent()[0].ApprovalID != "ap1" {
		t.Fatal("not delivered")
	}
	if err := (notify.Multi{bad}).Notify(context.Background(), req); err == nil {
		t.Fatal("all notifiers failing must be an error")
	}
	if err := (notify.Multi{}).Notify(context.Background(), req); err == nil {
		t.Fatal("no notifier must be an error")
	}
}
