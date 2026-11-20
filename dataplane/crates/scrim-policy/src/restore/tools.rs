// SPDX-License-Identifier: AGPL-3.0-only

//! Tool roles, the built-in tool table and restore settings from the snapshot.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use scrim_proto::v1 as pb;

use crate::escape::shell::{CommandSet, DATA_COMMANDS};
use crate::glob::Glob;

/// What a tool does with its arguments, which decides what may be restored into them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ToolRole {
    /// Nothing is restored (unknown tools, task and planning tools).
    None,
    /// Reads files or directories: display values are restored.
    Read,
    /// Searches files: display values are restored.
    Search,
    /// Runs a shell command: display values are restored where escaping keeps them data.
    Shell,
    /// Edits part of an existing file: a value is restored only where the call shows it is
    /// already in that file.
    Edit,
    /// Writes whole files: nothing is restored.
    Write,
    /// Can reach the network: nothing is restored.
    Network,
}

impl ToolRole {
    /// Converts a wire role; unspecified and unknown values are [`ToolRole::None`].
    pub fn from_proto(r: i32) -> ToolRole {
        match pb::ToolRole::try_from(r) {
            Ok(pb::ToolRole::Read) => ToolRole::Read,
            Ok(pb::ToolRole::Search) => ToolRole::Search,
            Ok(pb::ToolRole::Shell) => ToolRole::Shell,
            Ok(pb::ToolRole::Edit) => ToolRole::Edit,
            Ok(pb::ToolRole::Write) => ToolRole::Write,
            Ok(pb::ToolRole::Network) => ToolRole::Network,
            _ => ToolRole::None,
        }
    }

    /// Lower-case name, for audit.
    pub fn as_str(self) -> &'static str {
        match self {
            ToolRole::None => "none",
            ToolRole::Read => "read",
            ToolRole::Search => "search",
            ToolRole::Shell => "shell",
            ToolRole::Edit => "edit",
            ToolRole::Write => "write",
            ToolRole::Network => "network",
        }
    }

    /// Whether the role needs the complete arguments to decide (shell and edit look at where
    /// each placeholder sits).
    pub fn needs_arguments(self) -> bool {
        matches!(self, ToolRole::Shell | ToolRole::Edit)
    }
}

/// How one tool's arguments are read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolSpec {
    /// The role.
    pub role: ToolRole,
    /// Shell: the argument holding the command (string script or argv array).
    pub command_field: Arc<str>,
    /// Edit: arguments holding replaced text, at any depth.
    pub old_fields: Arc<[Arc<str>]>,
    /// Edit: arguments holding replacement text, at any depth.
    pub new_fields: Arc<[Arc<str>]>,
}

impl ToolSpec {
    /// A spec with the role's default fields.
    pub fn new(role: ToolRole) -> ToolSpec {
        ToolSpec {
            role,
            command_field: "command".into(),
            old_fields: ["old_string", "old_str"].map(Arc::from).into(),
            new_fields: ["new_string", "new_str"].map(Arc::from).into(),
        }
    }

    fn with_command(mut self, f: &str) -> ToolSpec {
        self.command_field = f.into();
        self
    }
}

/// The built-in tool table: Claude Code, Codex CLI and Gemini CLI tool names. Names not listed
/// (and not aliased) are unknown and get nothing.
pub const BUILTIN_TOOLS: &[(&str, ToolRole)] = &[
    // Claude Code.
    ("Read", ToolRole::Read),
    ("LS", ToolRole::Read),
    ("NotebookRead", ToolRole::Read),
    ("Grep", ToolRole::Search),
    ("Glob", ToolRole::Search),
    ("Bash", ToolRole::Shell),
    ("Edit", ToolRole::Edit),
    ("MultiEdit", ToolRole::Edit),
    ("Write", ToolRole::Write),
    ("NotebookEdit", ToolRole::Write),
    ("WebFetch", ToolRole::Network),
    ("WebSearch", ToolRole::Network),
    ("BashOutput", ToolRole::None),
    ("KillShell", ToolRole::None),
    ("Task", ToolRole::None),
    ("TodoWrite", ToolRole::None),
    // Codex CLI.
    ("shell", ToolRole::Shell),
    ("exec_command", ToolRole::Shell),
    ("apply_patch", ToolRole::Edit),
    ("read_file", ToolRole::Read),
    ("list_dir", ToolRole::Read),
    ("grep_files", ToolRole::Search),
    ("view_image", ToolRole::Read),
    ("web_search", ToolRole::Network),
    ("update_plan", ToolRole::None),
    // Gemini CLI.
    ("run_shell_command", ToolRole::Shell),
    ("read_many_files", ToolRole::Read),
    ("list_directory", ToolRole::Read),
    ("glob", ToolRole::Search),
    ("search_file_content", ToolRole::Search),
    ("replace", ToolRole::Edit),
    ("write_file", ToolRole::Write),
    ("web_fetch", ToolRole::Network),
    ("google_web_search", ToolRole::Network),
];

fn builtin(name: &str) -> Option<ToolSpec> {
    let role = BUILTIN_TOOLS.iter().find(|(n, _)| *n == name)?.1;
    let spec = ToolSpec::new(role);
    Some(if name == "exec_command" {
        spec.with_command("cmd")
    } else {
        spec
    })
}

/// How placeholders in displayed text are treated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DisplayMode {
    /// Display values are resolved.
    Values,
    /// Placeholders stay (screen sharing).
    Placeholders,
}

/// Why restore settings were rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// A tool alias is listed twice.
    #[error("restore: tool {0:?} listed twice")]
    DuplicateTool(String),
    /// A tool alias has an empty name.
    #[error("restore: tool alias with an empty name")]
    EmptyTool,
    /// A reveal pattern is not a valid glob.
    #[error("restore: reveal_credential_refs pattern {0:?}: trailing backslash")]
    Glob(String),
    /// An extra shell command is not a plain command name.
    #[error("restore: extra_shell_data_commands entry {0:?} is not a command name")]
    Command(String),
}

/// Restore settings, compiled from `Snapshot.restore`.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Display mode for assistant text.
    pub display: DisplayMode,
    tools: HashMap<String, ToolSpec>,
    builtin: bool,
    extra_commands: HashSet<String>,
    reveal: Vec<Glob>,
}

impl Default for Settings {
    /// What applies with no `restore` message: nothing is restored, not even displayed text.
    fn default() -> Settings {
        Settings {
            display: DisplayMode::Placeholders,
            tools: HashMap::new(),
            builtin: false,
            extra_commands: HashSet::new(),
            reveal: Vec::new(),
        }
    }
}

impl Settings {
    /// The usual configuration: display values shown, built-in tool table, no extras.
    pub fn standard() -> Settings {
        Settings {
            display: DisplayMode::Values,
            builtin: true,
            ..Settings::default()
        }
    }

    /// Compiles the wire settings. `None` is [`Settings::default`].
    pub fn from_proto(p: Option<&pb::RestoreSettings>) -> Result<Settings, SettingsError> {
        let Some(p) = p else {
            return Ok(Settings::default());
        };
        let display = match pb::DisplayMode::try_from(p.display_mode) {
            Ok(pb::DisplayMode::Values) => DisplayMode::Values,
            _ => DisplayMode::Placeholders,
        };
        let mut tools = HashMap::new();
        for a in &p.tools {
            if a.name.is_empty() {
                return Err(SettingsError::EmptyTool);
            }
            let mut spec = ToolSpec::new(ToolRole::from_proto(a.role));
            if !a.command_field.is_empty() {
                spec.command_field = a.command_field.as_str().into();
            }
            if !a.old_fields.is_empty() {
                spec.old_fields = a.old_fields.iter().map(|s| Arc::from(s.as_str())).collect();
            }
            if !a.new_fields.is_empty() {
                spec.new_fields = a.new_fields.iter().map(|s| Arc::from(s.as_str())).collect();
            }
            if tools.insert(a.name.clone(), spec).is_some() {
                return Err(SettingsError::DuplicateTool(a.name.clone()));
            }
        }
        let mut extra_commands = HashSet::new();
        for c in &p.extra_shell_data_commands {
            if c.is_empty()
                || !c
                    .chars()
                    .all(|x| x.is_ascii_alphanumeric() || matches!(x, '-' | '_' | '.' | '+'))
            {
                return Err(SettingsError::Command(c.clone()));
            }
            extra_commands.insert(c.clone());
        }
        let reveal = p
            .reveal_credential_refs
            .iter()
            .map(|g| Glob::new(g).map_err(|_| SettingsError::Glob(g.clone())))
            .collect::<Result<_, _>>()?;
        Ok(Settings {
            display,
            tools,
            builtin: !p.builtin_tools_disabled,
            extra_commands,
            reveal,
        })
    }

    /// Adds or replaces a tool alias.
    pub fn set_tool(&mut self, name: &str, spec: ToolSpec) {
        self.tools.insert(name.to_owned(), spec);
    }

    /// Adds a shell data command.
    pub fn add_shell_data_command(&mut self, name: &str) {
        self.extra_commands.insert(name.to_owned());
    }

    /// Adds a reveal pattern for credentials.
    pub fn add_reveal_credentials(&mut self, g: Glob) {
        self.reveal.push(g);
    }

    /// The spec for `tool`: an alias first, then the built-in table, else unknown.
    pub fn tool(&self, tool: &str) -> ToolSpec {
        if let Some(s) = self.tools.get(tool) {
            return s.clone();
        }
        if self.builtin
            && let Some(s) = builtin(tool)
        {
            return s;
        }
        ToolSpec::new(ToolRole::None)
    }

    /// Whether `scrim reveal` may resolve the credential `reference`.
    pub fn reveal_credential(&self, reference: &str) -> bool {
        self.reveal.iter().any(|g| g.matches(reference))
    }
}

impl CommandSet for Settings {
    fn is_data(&self, name: &str) -> bool {
        DATA_COMMANDS.contains(&name) || self.extra_commands.contains(name)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    #[test]
    fn builtin_and_aliases() {
        let s = Settings::standard();
        assert_eq!(s.tool("Bash").role, ToolRole::Shell);
        assert_eq!(s.tool("exec_command").command_field.as_ref(), "cmd");
        assert_eq!(s.tool("WebFetch").role, ToolRole::Network);
        assert_eq!(s.tool("run_shell").role, ToolRole::None);
        let p = pb::RestoreSettings {
            display_mode: pb::DisplayMode::Values as i32,
            tools: vec![
                pb::ToolAlias {
                    name: "run_shell".into(),
                    role: pb::ToolRole::Shell as i32,
                    command_field: "cmd".into(),
                    ..Default::default()
                },
                pb::ToolAlias {
                    name: "Bash".into(),
                    role: pb::ToolRole::Unspecified as i32,
                    ..Default::default()
                },
                pb::ToolAlias {
                    name: "patch".into(),
                    role: pb::ToolRole::Edit as i32,
                    old_fields: vec!["from".into()],
                    new_fields: vec!["to".into()],
                    ..Default::default()
                },
            ],
            extra_shell_data_commands: vec!["mytool".into()],
            reveal_credential_refs: vec!["bao://kv/dev/**".into()],
            ..Default::default()
        };
        let s = Settings::from_proto(Some(&p)).unwrap();
        assert_eq!(s.display, DisplayMode::Values);
        assert_eq!(s.tool("run_shell").role, ToolRole::Shell);
        assert_eq!(s.tool("run_shell").command_field.as_ref(), "cmd");
        assert_eq!(
            s.tool("Bash").role,
            ToolRole::None,
            "alias overrides built-in"
        );
        assert_eq!(s.tool("patch").old_fields[0].as_ref(), "from");
        assert!(s.is_data("mytool") && s.is_data("cat") && !s.is_data("sh"));
        assert!(s.reveal_credential("bao://kv/dev/a/b"));
        assert!(!s.reveal_credential("bao://kv/prod/a"));

        let mut off = p.clone();
        off.builtin_tools_disabled = true;
        off.display_mode = 0;
        let s = Settings::from_proto(Some(&off)).unwrap();
        assert_eq!(s.tool("Read").role, ToolRole::None);
        assert_eq!(s.display, DisplayMode::Placeholders);

        let mut dup = p.clone();
        dup.tools.push(dup.tools[0].clone());
        assert!(matches!(
            Settings::from_proto(Some(&dup)),
            Err(SettingsError::DuplicateTool(_))
        ));
        let mut bad = p.clone();
        bad.reveal_credential_refs = vec!["a\\".into()];
        assert!(matches!(
            Settings::from_proto(Some(&bad)),
            Err(SettingsError::Glob(_))
        ));
        let mut bad = p.clone();
        bad.extra_shell_data_commands = vec!["a b".into()];
        assert!(matches!(
            Settings::from_proto(Some(&bad)),
            Err(SettingsError::Command(_))
        ));
        let mut bad = p;
        bad.tools[0].name.clear();
        assert_eq!(
            Settings::from_proto(Some(&bad)).unwrap_err(),
            SettingsError::EmptyTool
        );

        let none = Settings::from_proto(None).unwrap();
        assert_eq!(none.display, DisplayMode::Placeholders);
        assert_eq!(none.tool("Read").role, ToolRole::None);
        for r in 0..9 {
            let role = ToolRole::from_proto(r);
            assert!(!role.as_str().is_empty());
        }
        assert!(ToolRole::Shell.needs_arguments() && !ToolRole::Read.needs_arguments());
    }
}
