// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"fmt"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
)

// Restore settings (specs/redaction "Resolution follows tool policy",
// "Tool aliases", "Display modes", "Share and reveal"). They travel in every
// snapshot, so a reload takes effect with the next push.
var (
	// DisplayMode decides placeholders in text the agent displays.
	DisplayMode = config.Register(config.Spec[string]{
		Key:     "restore.display-mode",
		Default: "values",
		Enum:    []string{"values", "placeholders"},
		Flag:    true,
		Description: "What the agent displays for display-class values: values resolves them in assistant text, " +
			"placeholders keeps placeholders (for example while screen sharing). Tool arguments follow the tool roles either way; credentials are never restored.",
	})
	// BuiltinTools turns the built-in tool table on or off.
	BuiltinTools = config.Register(config.Spec[bool]{
		Key:         "restore.builtin-tools",
		Default:     true,
		Description: "Use the built-in table of agent tool roles (Claude Code, Codex). When false only restore.tools have roles and every other tool is unknown, which restores nothing.",
	})
	// ShellDataCommands widens what a shell restore may feed values to.
	ShellDataCommands = config.Register(config.Spec[[]string]{
		Key:       "restore.allow-shell-data-commands",
		Default:   []string{},
		Weakening: true,
		Description: "Commands a shell-role restore may pass display values to, beyond the built-in list of commands that run no code. " +
			"A listed command that interprets an argument as code turns a restored value into code.",
	})
	// RevealCredentials lets `scrim reveal` resolve matching credentials.
	RevealCredentials = config.Register(config.Spec[[]string]{
		Key:       "restore.allow-reveal-credentials",
		Default:   []string{},
		Weakening: true,
		Description: "Glob patterns over store references of credentials that scrim reveal may resolve locally. Empty means reveal never resolves a credential. " +
			"Restore into responses never resolves credentials, whatever this holds.",
	})
	// Tools are tool aliases.
	Tools = config.RegisterCollection(config.CollectionSpec{
		Key: toolsKey,
		Description: "Tool aliases by name: `role` (none, read, search, shell, edit, write, network), optional `name` (the tool name exactly as the model calls it, " +
			"default the instance name), `command-field` for shell, `old-fields` and `new-fields` for edit. An alias overrides the built-in table.",
		RequiredFields: []string{"role"},
		Validate: func(inst config.Instance) error {
			_, err := toolAliasOf(inst)
			return err
		},
	})
)

const toolsKey = "restore.tools"

var roles = map[string]pb.ToolRole{
	"none": pb.ToolRole_TOOL_ROLE_NONE, "read": pb.ToolRole_TOOL_ROLE_READ, "search": pb.ToolRole_TOOL_ROLE_SEARCH,
	"shell": pb.ToolRole_TOOL_ROLE_SHELL, "edit": pb.ToolRole_TOOL_ROLE_EDIT, "write": pb.ToolRole_TOOL_ROLE_WRITE,
	"network": pb.ToolRole_TOOL_ROLE_NETWORK,
}

func toolAliasOf(inst config.Instance) (*pb.ToolAlias, error) {
	where := func(f string) string { return inst.Key(toolsKey, f) }
	for k := range inst.Fields {
		switch k {
		case "role", "name", "command-field", "old-fields", "new-fields":
		default:
			return nil, fmt.Errorf("%s.%s: unknown field %s", toolsKey, inst.Name, k)
		}
	}
	role, ok := roles[strings.ToLower(inst.String("role"))]
	if !ok {
		return nil, fmt.Errorf("%s: must be one of none, read, search, shell, edit, write, network", where("role"))
	}
	a := &pb.ToolAlias{Name: inst.String("name"), Role: role, CommandField: inst.String("command-field")}
	if a.Name == "" {
		a.Name = inst.Name
	}
	var err error
	if a.OldFields, err = stringList(inst, "old-fields"); err != nil {
		return nil, fmt.Errorf("%s: %w", where("old-fields"), err)
	}
	if a.NewFields, err = stringList(inst, "new-fields"); err != nil {
		return nil, fmt.Errorf("%s: %w", where("new-fields"), err)
	}
	if a.CommandField != "" && role != pb.ToolRole_TOOL_ROLE_SHELL {
		return nil, fmt.Errorf("%s: only a shell tool has a command field", where("command-field"))
	}
	if (len(a.OldFields) > 0 || len(a.NewFields) > 0) && role != pb.ToolRole_TOOL_ROLE_EDIT {
		return nil, fmt.Errorf("%s.%s: only an edit tool has old-fields and new-fields", toolsKey, inst.Name)
	}
	return a, nil
}

// restoreSettings builds Snapshot.restore. Aliases naming the same tool
// twice would reject the snapshot; the second is dropped (the collection's
// own validation names it at load).
func restoreSettings(cfg *config.Config) *pb.RestoreSettings {
	r := &pb.RestoreSettings{
		DisplayMode:            pb.DisplayMode_DISPLAY_MODE_VALUES,
		BuiltinToolsDisabled:   !BuiltinTools.Get(cfg),
		ExtraShellDataCommands: slices.Clone(ShellDataCommands.Get(cfg)),
		RevealCredentialRefs:   slices.Clone(RevealCredentials.Get(cfg)),
	}
	if DisplayMode.Get(cfg) == "placeholders" {
		r.DisplayMode = pb.DisplayMode_DISPLAY_MODE_PLACEHOLDERS
	}
	seen := map[string]bool{}
	for _, inst := range Tools.Get(cfg) {
		a, err := toolAliasOf(inst)
		if err != nil || seen[a.GetName()] {
			continue
		}
		seen[a.GetName()] = true
		r.Tools = append(r.Tools, a)
	}
	return r
}
