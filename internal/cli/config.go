// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/heliopsy/scrim/internal/config"
)

// errInvalidConfig is returned by `config validate` after the problems are
// printed, so the exit code is non-zero without printing them twice.
var errInvalidConfig = errors.New("configuration is invalid")

// Config inspects and validates configuration.
func (Commands) Config(e *Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate configuration",
		Long: "Inspect and validate scrim's configuration: built-in defaults, the profile, config files " +
			"with their includes, SCRIM_* environment variables and flags, in rising precedence.",
	}
	cmd.AddCommand(configValidate(e), configShow(e), configSchema(e), configDocs(e))
	return cmd
}

func configValidate(e *Env) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check the merged configuration without starting anything",
		Long: "Check the full merged configuration (files, environment, flags, secret references) " +
			"without starting any listener. Every problem is listed with its key and source, and the " +
			"command exits non-zero when there is one. Store references are checked for syntax only: " +
			"validate does not contact secret stores.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := e.Config()
			return writeValidation(cmd.OutOrStdout(), output, c, err)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	return cmd
}

type validationProblem struct {
	Key     string `json:"key,omitempty"`
	Source  string `json:"source,omitempty"`
	Message string `json:"message"`
}

type validationReport struct {
	Valid      bool                `json:"valid"`
	Files      []string            `json:"files"`
	Profile    string              `json:"profile,omitempty"`
	Problems   []validationProblem `json:"problems,omitempty"`
	Warnings   []config.Warning    `json:"warnings,omitempty"`
	Unresolved []string            `json:"unresolvedStoreReferences,omitempty"`
}

func writeValidation(w io.Writer, format string, c *config.Config, err error) error {
	rep := validationReport{Valid: err == nil, Files: []string{}}
	if c != nil {
		rep.Files = c.Files()
		rep.Profile = c.Profile()
		rep.Warnings = c.Warnings()
		rep.Unresolved = c.Unresolved()
	}
	problems := config.Problems(err)
	for _, p := range problems {
		vp := validationProblem{Key: p.Key, Message: p.Err.Error()}
		if p.Source.Kind != "" {
			vp.Source = p.Source.String()
		}
		rep.Problems = append(rep.Problems, vp)
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if werr := enc.Encode(rep); werr != nil {
			return werr
		}
	case "text":
		var b bytes.Buffer
		if rep.Valid {
			fmt.Fprintf(&b, "configuration is valid (profile %s)\n", rep.Profile)
			if len(rep.Files) == 0 {
				fmt.Fprintln(&b, "  no config file: defaults, environment and flags only")
			}
			for _, f := range rep.Files {
				fmt.Fprintf(&b, "  file: %s\n", f)
			}
			for _, warn := range rep.Warnings {
				fmt.Fprintf(&b, "warning: %s\n", warn)
			}
			for _, k := range rep.Unresolved {
				fmt.Fprintf(&b, "note: %s holds a store reference; validate checks its syntax but does not contact the store\n", k)
			}
		} else {
			fmt.Fprintf(&b, "configuration is invalid: %d problem(s)\n", len(problems))
			for _, p := range problems {
				fmt.Fprintf(&b, "error: %s\n", p)
			}
		}
		if _, werr := w.Write(b.Bytes()); werr != nil {
			return werr
		}
	default:
		return fmt.Errorf("unknown output format %q (text, json)", format)
	}
	if !rep.Valid {
		return errInvalidConfig
	}
	return nil
}

func configShow(e *Env) *cobra.Command {
	var (
		output    string
		effective bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print configuration values and where each came from",
		Long: "Print the settings that are set (with --effective, every setting) with the value in " +
			"effect and its source: default, profile, file and line, environment variable or flag. " +
			"Secret-valued settings show their reference form and a masked value, never the value.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := e.Config()
			if err != nil {
				return writeValidation(cmd.ErrOrStderr(), "text", nil, err)
			}
			return config.WriteEffective(cmd.OutOrStdout(), c, config.ShowOptions{Format: output, OnlySet: !effective})
		},
	}
	cmd.Flags().BoolVar(&effective, "effective", false, "show every setting, including those at their default")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	return cmd
}

func configSchema(e *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of the config file",
		Long: "Print the JSON Schema (draft 2020-12) of the config file for " + config.APIVersion +
			", generated from the same registry scrim validates against.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := config.Schema(e.Registry)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
}

func configDocs(e *Env) *cobra.Command {
	var update string
	cmd := &cobra.Command{
		Use:    "docs",
		Short:  "Print the generated settings reference in Markdown",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ref := config.Reference(e.Registry)
			if update == "" {
				_, err := cmd.OutOrStdout().Write(ref)
				return err
			}
			doc, err := os.ReadFile(update) // #nosec G304 -- developer-supplied path
			if err != nil {
				return err
			}
			out, err := config.SpliceReference(doc, ref)
			if err != nil {
				return err
			}
			return os.WriteFile(update, out, 0o644) // #nosec G306 -- documentation file, world-readable on purpose
		},
	}
	cmd.Flags().StringVar(&update, "update", "", "replace the generated section of this Markdown file in place")
	return cmd
}
