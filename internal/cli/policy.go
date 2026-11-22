// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/stores"
)

// Policy checks, evaluates and compiles rules files offline.
func (Commands) Policy(e *Env) *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Check, evaluate and compile policy rules"}
	load := func(args []string) (*policy.RuleSet, error) {
		cfg, err := e.Config()
		if err != nil {
			return nil, err
		}
		var pc policy.Config
		if len(args) == 1 {
			if pc, err = policy.LoadFile(args[0]); err != nil {
				return nil, err
			}
			if pc.Default == "" {
				pc.Default = policy.DefaultEffect.Get(cfg)
			}
			if pc, err = policy.WithBuiltins(cfg, pc); err != nil {
				return nil, err
			}
		} else if pc, err = policy.FromConfig(cfg); err != nil {
			return nil, err
		}
		return policy.Compile(pc)
	}
	check := &cobra.Command{
		Use:   "check [rules-file]",
		Short: "Validate a rules file (default: policy.rules-file)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rs, err := load(args)
			if err != nil {
				return err
			}
			snap := rs.Snapshot(0, false)
			local := 0
			for _, r := range snap.Rules {
				residual := false
				for _, cl := range r.Clauses {
					residual = residual || cl.Residual
				}
				if !residual {
					local++
				}
			}
			builtin := 0
			for _, r := range snap.Rules {
				if strings.HasPrefix(r.Name, policy.BuiltinPrefix) {
					builtin++
				}
			}
			_, err = fmt.Fprintf(e.Stdout, "ok: %d rules (%d built-in), default %s, %d decided entirely in the data plane\n",
				len(snap.Rules), builtin, snap.Default, local)
			return err
		},
	}

	var (
		reqFile string
		r       evalFlags
	)
	eval := &cobra.Command{
		Use:   "eval [rules-file]",
		Short: "Evaluate one request against the rules and explain the decision",
		Long: "Evaluate one request against the rules and explain the decision. The request comes from flags " +
			"or from --request, a JSON file in the conformance vector format (op, agent, secret, provider, dest, tool).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rs, err := load(args)
			if err != nil {
				return err
			}
			req, err := r.request(reqFile)
			if err != nil {
				return err
			}
			snap := rs.Snapshot(0, false)
			out := struct {
				policy.Result
				DataPlane policy.LocalResult `json:"data_plane"`
			}{rs.Evaluate(req), snap.Evaluate(req)}
			enc := json.NewEncoder(e.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	f := eval.Flags()
	f.StringVar(&reqFile, "request", "", "JSON request file")
	f.StringVar(&r.op, "op", "", "action (inject, store.write, ...)")
	f.StringVar(&r.agent, "agent", "", "agent ID")
	f.StringVar(&r.kind, "agent-kind", "session", "how the agent was identified (peer, session, k8s, mtls; empty for unknown)")
	f.StringToStringVar(&r.labels, "agent-label", nil, "agent labels, key=value")
	f.StringVar(&r.ref, "ref", "", "secret reference")
	f.StringVar(&r.name, "name", "", "catalog name")
	f.StringVar(&r.class, "class", "", "secret class")
	f.StringToStringVar(&r.slabels, "secret-label", nil, "secret labels, key=value")
	f.StringArrayVar(&r.label, "label", nil, "one secret label, key=value (repeatable; a value may contain commas, "+
		"as multi-valued store labels do); `scrim catalog labels` lists a secret's labels")
	f.StringVar(&r.provider, "provider", "", "model provider")
	f.StringVar(&r.host, "host", "", "destination host")
	f.StringVar(&r.method, "method", "", "HTTP method")
	f.StringVar(&r.path, "path", "", "request path")
	f.StringVar(&r.tool, "tool", "", "tool name")
	f.StringVar(&r.command, "command", "", "command")

	snapshot := &cobra.Command{
		Use:   "snapshot [rules-file]",
		Short: "Print the decision table the data plane receives",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rs, err := load(args)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(e.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rs.Snapshot(0, false))
		},
	}
	c.AddCommand(check, eval, snapshot)
	return c
}

type evalFlags struct {
	op, agent, kind, ref, name, class, provider, host, method, path, tool, command string
	labels, slabels                                                                map[string]string
	label                                                                          []string
}

// vectorFile is the JSON request format of `policy eval --request`, the same
// as the conformance vectors.
type vectorFile struct {
	Op       string            `json:"op"`
	Agent    policy.RuleAgent  `json:"agent"`
	Secret   policy.RuleSecret `json:"secret"`
	Provider string            `json:"provider"`
	Dest     policy.RuleDest   `json:"dest"`
	Tool     policy.RuleTool   `json:"tool"`
}

func (r *evalFlags) request(file string) (policy.Request, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return policy.Request{}, err
		}
		var v vectorFile
		if err := json.Unmarshal(data, &v); err != nil {
			return policy.Request{}, fmt.Errorf("%s: %w", file, err)
		}
		r.op, r.agent, r.kind, r.labels = v.Op, v.Agent.ID, v.Agent.Kind, v.Agent.Labels
		r.ref, r.name, r.class, r.slabels = v.Secret.Ref, v.Secret.Name, v.Secret.Class, v.Secret.Labels
		r.provider, r.host, r.method, r.path = v.Provider, v.Dest.Host, v.Dest.Method, v.Dest.Path
		r.tool, r.command = v.Tool.Name, v.Tool.Command
	}
	for _, kv := range r.label {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return policy.Request{}, fmt.Errorf("--label %q: want key=value", kv)
		}
		if r.slabels == nil {
			r.slabels = map[string]string{}
		}
		r.slabels[k] = v
	}
	req := policy.Request{
		Action: policy.Action(r.op),
		Agent:  policy.Agent{ID: r.agent, Kind: policy.IdentityKind(r.kind), Labels: r.labels},
		Name:   r.name, SecretClass: r.class, SecretLabels: r.slabels,
		Provider: r.provider, Host: r.host, Method: r.method, Path: r.path, Tool: r.tool, Command: r.command,
	}
	if r.agent == "" {
		req.Agent.Kind = policy.IdentityUnknown
	}
	if r.ref != "" {
		ref, err := stores.ParseRef(r.ref)
		if err != nil {
			return policy.Request{}, err
		}
		req.Ref = ref
	}
	return req, nil
}
