// SPDX-License-Identifier: AGPL-3.0-only

package app_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/policy"
)

func TestNewDefaults(t *testing.T) {
	var logs bytes.Buffer
	a, err := app.New(context.Background(), config.MustLoadDefaults(config.Default), &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	d, err := a.Policy.Decide(context.Background(), policy.Request{})
	if err != nil || d.Effect != policy.Deny {
		t.Fatalf("default policy = %+v, %v", d, err)
	}
	if rep := a.Health.Run(context.Background(), true); rep.Status != "ok" {
		t.Fatalf("readiness = %+v", rep)
	}
}

func TestWeakenedSettingWarns(t *testing.T) {
	cfg, err := config.Load(config.Default, config.EnvLayer([]string{"SCRIM_POLICY_DEFAULT=allow"}))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	a, err := app.New(context.Background(), cfg, &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if !strings.Contains(logs.String(), "weakened protection active") || !strings.Contains(logs.String(), "policy.default") {
		t.Fatalf("no start-up warning: %s", logs.String())
	}
}
