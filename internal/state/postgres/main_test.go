// SPDX-License-Identifier: AGPL-3.0-only

package postgres_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The tests need a PostgreSQL server. SCRIM_TEST_POSTGRES_DSN points them at
// an existing one (CI service containers); otherwise TestMain starts a
// throwaway container with rootless podman and removes it afterwards. When
// neither is possible every test skips with the recorded reason.
const defaultImage = "docker.io/library/postgres:18.6-alpine3.24"

var (
	adminDSN   string
	skipReason string
	dbSeq      atomic.Int64
)

func TestMain(m *testing.M) {
	cleanup := setup()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func setup() func() {
	if dsn := os.Getenv("SCRIM_TEST_POSTGRES_DSN"); dsn != "" {
		adminDSN = dsn
		return func() {}
	}
	if _, err := exec.LookPath("podman"); err != nil {
		skipReason = "podman not found and SCRIM_TEST_POSTGRES_DSN not set"
		return func() {}
	}
	image := os.Getenv("SCRIM_TEST_POSTGRES_IMAGE")
	if image == "" {
		image = defaultImage
	}
	name := "scrim-state-pg-" + randHex(4)
	password := randHex(16)
	out, err := exec.Command("podman", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD="+password, "-e", "POSTGRES_USER=scrim", "-e", "POSTGRES_DB=scrim",
		"-p", "127.0.0.1::5432", image,
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off").CombinedOutput()
	if err != nil {
		skipReason = fmt.Sprintf("podman run %s failed: %v: %s", image, err, strings.TrimSpace(string(out)))
		return func() {}
	}
	remove := func() { _ = exec.Command("podman", "rm", "-f", "-v", name).Run() }
	port, err := exec.Command("podman", "port", name, "5432/tcp").Output()
	if err != nil {
		remove()
		skipReason = fmt.Sprintf("podman port %s: %v", name, err)
		return func() {}
	}
	hostport := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	adminDSN = fmt.Sprintf("postgres://scrim:%s@%s/scrim?sslmode=disable", password, hostport)
	if err := waitReady(adminDSN, 60*time.Second); err != nil {
		remove()
		skipReason = fmt.Sprintf("postgres in %s never became ready: %v", name, err)
		adminDSN = ""
	}
	return remove
}

func waitReady(dsn string, d time.Duration) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	deadline := time.Now().Add(d)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// freshDSN creates an empty database for one test and returns its DSN.
func freshDSN(t *testing.T) string {
	t.Helper()
	if adminDSN == "" {
		t.Skip("postgres unavailable: " + skipReason)
	}
	db, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	name := fmt.Sprintf("scrim_t%d_%s", dbSeq.Add(1), randHex(3))
	if _, err := db.ExecContext(t.Context(), "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		db, err := sql.Open("pgx", adminDSN)
		if err == nil {
			_, _ = db.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
			_ = db.Close()
		}
	})
	i := strings.LastIndex(adminDSN, "/")
	q := strings.Index(adminDSN[i:], "?")
	return adminDSN[:i+1] + name + adminDSN[i+q:]
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
