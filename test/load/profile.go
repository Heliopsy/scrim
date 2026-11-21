// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Duration reads and writes Go duration strings in JSON.
type Duration time.Duration

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// UnmarshalJSON reads a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// RunParams size one run.
type RunParams struct {
	Replicas          int      `json:"replicas"`
	Streams           int      `json:"streams"`
	Sessions          int      `json:"sessions"`
	ApprovalWorkers   int      `json:"approval_workers"`
	Duration          Duration `json:"duration"`
	Warmup            Duration `json:"warmup"`
	BodyKB            int      `json:"body_kb"`
	BulkSecrets       int      `json:"bulk_secrets"`
	Notes             int      `json:"notes"`
	Creds             int      `json:"creds"`
	SecretsPerRequest int      `json:"secrets_per_request"`
	ChunkRunes        int      `json:"chunk_runes"`
	ReplyRunes        int      `json:"reply_runes"`
	ChunkInterval     Duration `json:"chunk_interval"`
	ThinkTime         Duration `json:"think_time"`
	ApprovalInterval  Duration `json:"approval_interval"`
	ReplicaCPUs       string   `json:"replica_cpus"`
	ReplicaMemory     string   `json:"replica_memory"`
	DriverCPUs        string   `json:"driver_cpus"`
	DriverMemory      string   `json:"driver_memory"`
	PostgresCPUs      string   `json:"postgres_cpus"`
	PostgresMemory    string   `json:"postgres_memory"`
}

// Thresholds decide pass or fail. Zero limits on correctness are absolute.
type Thresholds struct {
	MaxLeaks                 int     `json:"max_leaks"`
	MaxRestoreFailures       int     `json:"max_restore_failures"`
	MaxInjectionFailures     int     `json:"max_injection_failures"`
	MaxApprovalFailures      int     `json:"max_approval_failures"`
	MaxErrorRate             float64 `json:"max_error_rate"`
	MinStreamsReached        float64 `json:"min_mean_streams_fraction"`
	MinLLMRequestsPerSecond  float64 `json:"min_llm_requests_per_second"`
	ScrimRequestAddedP99Ms   float64 `json:"scrim_request_added_p99_ms"`
	ScrimChunkP99Us          float64 `json:"scrim_chunk_p99_us"`
	ClientAddedP99Ms         float64 `json:"client_added_p99_ms"`
	ApprovalReleaseP99Ms     float64 `json:"approval_release_p99_ms"`
	MaxReplicaMemoryFraction float64 `json:"max_replica_memory_fraction"`
	MaxMemoryPerStreamKiB    float64 `json:"max_memory_per_stream_kib"`
}

// Profile is one entry of profiles.json.
type Profile struct {
	Comment    string     `json:"comment,omitempty"`
	Run        RunParams  `json:"run"`
	Thresholds Thresholds `json:"thresholds"`
}

type profileFile struct {
	Profiles map[string]Profile `json:"profiles"`
}

func loadProfile(path, name string) (Profile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // a path the operator names
	if err != nil {
		return Profile{}, err
	}
	var f profileFile
	if err := json.Unmarshal(b, &f); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	p, ok := f.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("%s: no profile %q", path, name)
	}
	return p, p.Run.validate()
}

func (r RunParams) validate() error {
	switch {
	case r.Replicas < 3:
		return fmt.Errorf("replicas %d: the test needs at least 3 (hold, decide and revoke on different replicas)", r.Replicas)
	case r.Streams < 1 || r.Sessions < 1 || r.Sessions > r.Streams:
		return fmt.Errorf("streams %d and sessions %d: need 1 <= sessions <= streams", r.Streams, r.Sessions)
	case r.ApprovalWorkers < 1:
		return fmt.Errorf("approval_workers %d: need at least 1", r.ApprovalWorkers)
	case r.Duration.D() <= 0 || r.Warmup.D() < 0:
		return fmt.Errorf("duration %s, warmup %s", r.Duration.D(), r.Warmup.D())
	case r.BulkSecrets < r.SecretsPerRequest || r.Notes < 1 || r.Creds < 1:
		return fmt.Errorf("secret sets too small (bulk %d, notes %d, creds %d)", r.BulkSecrets, r.Notes, r.Creds)
	case r.ChunkRunes < 1 || r.BodyKB < 1:
		return fmt.Errorf("chunk_runes %d, body_kb %d", r.ChunkRunes, r.BodyKB)
	}
	return nil
}

// Endpoints of one replica, all on the host's loopback.
type Endpoints struct {
	Name      string `json:"name"`
	LLM       string `json:"llm"`
	Forward   string `json:"forward"`
	Admin     string `json:"admin"`
	Metrics   string `json:"metrics"`
	APISocket string `json:"api_socket"`
}

// Plan is what run hands the load generator (run/plan.json).
type Plan struct {
	Profile      string      `json:"profile"`
	Run          RunParams   `json:"run"`
	Replicas     []Endpoints `json:"replicas"`
	ProviderAddr string      `json:"provider_addr"`
	ToolAddr     string      `json:"tool_addr"`
	SeedsDir     string      `json:"seeds_dir"`
	ToolCertFile string      `json:"tool_cert_file"`
	ToolKeyFile  string      `json:"tool_key_file"`
	AdminToken   string      `json:"admin_token"`
	ResultFile   string      `json:"result_file"`
	// Sabotage names a deliberate break, for watching the checks fail.
	Sabotage string `json:"sabotage,omitempty"`
}
