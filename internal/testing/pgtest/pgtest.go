// SPDX-License-Identifier: AGPL-3.0-only

// Package pgtest gives tests a PostgreSQL server. SCRIM_TEST_POSTGRES_DSN
// points them at an existing one (CI service containers); otherwise the
// first [FreshDSN] starts a throwaway container with rootless podman, which
// [Stop] removes. When neither is possible every caller skips with the
// recorded reason. A package using it calls Stop from TestMain after m.Run.
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver
)

// DefaultImage is the image started when SCRIM_TEST_POSTGRES_IMAGE is unset.
const DefaultImage = "docker.io/library/postgres:18.6-alpine3.24"

var (
	once       sync.Once
	adminDSN   string
	skipReason string
	remove     = func() {}
	dbSeq      atomic.Int64
)

func setup() {
	if dsn := os.Getenv("SCRIM_TEST_POSTGRES_DSN"); dsn != "" {
		adminDSN = dsn
		return
	}
	if _, err := exec.LookPath("podman"); err != nil {
		skipReason = "podman not found and SCRIM_TEST_POSTGRES_DSN not set"
		return
	}
	image := os.Getenv("SCRIM_TEST_POSTGRES_IMAGE")
	if image == "" {
		image = DefaultImage
	}
	name := "scrim-test-pg-" + randHex(4)
	password := randHex(16)
	out, err := exec.Command("podman", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD="+password, "-e", "POSTGRES_USER=scrim", "-e", "POSTGRES_DB=scrim",
		"-p", "127.0.0.1::5432", image,
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off").CombinedOutput()
	if err != nil {
		skipReason = fmt.Sprintf("podman run %s failed: %v: %s", image, err, strings.TrimSpace(string(out)))
		return
	}
	rm := func() { _ = exec.Command("podman", "rm", "-f", "-v", name).Run() }
	port, err := exec.Command("podman", "port", name, "5432/tcp").Output()
	if err != nil {
		rm()
		skipReason = fmt.Sprintf("podman port %s: %v", name, err)
		return
	}
	hostport := strings.TrimSpace(strings.Split(string(port), "\n")[0])
	dsn := fmt.Sprintf("postgres://scrim:%s@%s/scrim?sslmode=disable", password, hostport)
	if err := waitReady(dsn, 60*time.Second); err != nil {
		rm()
		skipReason = fmt.Sprintf("postgres in %s never became ready: %v", name, err)
		return
	}
	adminDSN, remove = dsn, rm
}

// Stop removes the container the package started, if any.
func Stop() { remove() }

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

// FreshDSN creates an empty database for one test, dropped when it ends,
// and returns its DSN. It skips the test when no server is available.
func FreshDSN(t testing.TB) string {
	t.Helper()
	once.Do(setup)
	if adminDSN == "" {
		t.Skip("postgres unavailable: " + skipReason)
	}
	db, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	name := fmt.Sprintf("scrim_t%d_%s", dbSeq.Add(1), randHex(3))
	if _, err := db.ExecContext(context.Background(), "CREATE DATABASE "+name); err != nil {
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
	if q < 0 {
		return adminDSN[:i+1] + name
	}
	return adminDSN[:i+1] + name + adminDSN[i+q:]
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
