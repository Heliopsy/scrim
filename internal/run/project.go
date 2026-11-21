// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/projectscan"
)

// scanProject scans the agent's working directory and, for a real run,
// registers what it found with scrim before the agent starts
// (specs/credential-injection "Secrets in project files"). A failed
// registration refuses the run: those values would reach the provider.
func (p *Prepared) scanProject(ctx context.Context) error {
	dir := p.opts.Dir
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return refused("scanning the project: %v", err)
		}
		dir = wd
	}
	if home, err := os.UserHomeDir(); err == nil && sameDir(dir, home) || sameDir(dir, "/") {
		p.Plan.Warnings = append(p.Plan.Warnings, "project files are not scanned: the working directory is "+dir+", not a project")
		return nil
	}
	res, err := projectscan.Scan(dir, projectscan.Options{})
	if err != nil {
		return refused("scanning the project %s failed: %v (run.scan-project=false skips the scan)", dir, err)
	}
	for _, f := range res.Movable() {
		p.Plan.Project = append(p.Plan.Project, f.String())
	}
	for _, s := range res.Skipped {
		p.Plan.Warnings = append(p.Plan.Warnings, "project file not scanned: "+s)
	}
	if p.opts.dry() || p.client == nil {
		res.Wipe()
		return nil
	}
	if len(res.Findings) == 0 {
		p.project = res // watched: values written later are registered then
		return nil
	}
	if err := p.register(ctx, res); err != nil {
		res.Wipe()
		return refused("registering the secret values found in project files failed: %v (run.scan-project=false skips the scan)", err)
	}
	p.project = res
	if n := len(p.Plan.Project); n > 0 {
		p.Plan.Warnings = append(p.Plan.Warnings, fmt.Sprintf(
			"%d secret values in project files are redacted for this session; `scrim project move` moves them into a store", n))
	}
	return nil
}

func (p *Prepared) register(ctx context.Context, res *projectscan.Result) error {
	values := make([]localapi.NamedValue, 0, len(res.Findings))
	for _, f := range res.Findings {
		values = append(values, localapi.NamedValue{Name: f.Name(), Value: f.Value})
	}
	_, err := p.client.RegisterValues(ctx, values)
	return err
}

// watchProject rescans the project every ScanInterval while the agent runs
// and registers the new set when anything changed.
func (p *Prepared) watchProject(ctx context.Context) {
	if p.project == nil || p.opts.ScanInterval <= 0 || p.client == nil {
		return
	}
	t := time.NewTicker(p.opts.ScanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		res, err := projectscan.Scan(p.project.Dir, projectscan.Options{})
		if err != nil {
			continue
		}
		if res.Same(p.project) {
			res.Wipe()
			continue
		}
		if err := p.register(ctx, res); err != nil {
			res.Wipe()
			p.opts.say("WARNING: project files changed but their values could not be registered for redaction: %v", err)
			continue
		}
		p.project.Wipe()
		p.project = res
		if p.opts.Log != nil {
			p.opts.Log.Info("project files changed; their secret values were registered again", "values", len(res.Findings))
		}
	}
}

func sameDir(a, b string) bool {
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}
