// SPDX-License-Identifier: AGPL-3.0-only

// Package profiles holds scrim's tool profiles for command-line tools
// (specs/credential-injection, "Placeholder credentials for command-line
// tools", "Built-in tool profiles", "Environment overrides before file
// tricks", "Tools that print their own credentials"; tasks 10a.1, 10a.5,
// 10a.6, 10a.9, 10a.10).
//
// A profile says where a tool (gh, git, kubectl, aws, ...) reads its
// credentials, which hosts it sends them to, and what `scrim run` generates
// so that the tool finds placeholders there. Credentials stay placeholders
// in the agent's environment and files; the tool proxy swaps them for the
// real values on connections to the bound hosts (design D5).
//
// # Format
//
// Built-in profiles are embedded from builtin/<name>.yaml. Users add or
// override profiles in the configuration collection `tool-profiles.<name>`
// with the same fields; a name matching a built-in replaces the fields it
// sets and merges params key by key.
//
//	description: GitHub CLI (gh)
//	tools: [gh]                     # executables, for display and tests
//	requires: []                    # profiles applied together with this one
//	credentials:                    # slots catalog entries fill
//	  - name: token
//	    hosts: [api.github.com]     # bound when the entry names no hosts
//	    inject: ["header:Authorization"]
//	    required: true
//	params: {username: x-access-token}
//	env:   {GH_TOKEN: '{{ placeholder "token" }}', GH_CONFIG_DIR: '{{ path "config" }}'}
//	unset: [GITHUB_TOKEN, "TF_TOKEN_*"]   # inherited variables removed
//	dirs:  [config]                 # created empty in the profile directory
//	bin:   [docker-credential-scrim] # linked to scrim, first on PATH
//	files: [{path: npmrc, content: "..."}]
//	paths: [{home: .config/gh/hosts.yml, generated: ""}]
//	test:  {command: [gh, auth, token], expect: '{{ placeholder "token" }}'}
//
// A catalog entry fills a slot by naming it in its tools list: `gh` for the
// profile's first slot, `aws.secret-access-key` for another. Such an entry
// with no hosts takes the slot's hosts and injection locations, and one
// with no placeholder gets the declared placeholder SCRIM_<NAME>
// (catalog.RegisterToolDefaults, applied by catalog.Load in every process
// that links this package; internal/app does).
//
// Templates are text/template with these functions: placeholder SLOT (the
// first filling entry's placeholder, "" when unfilled), creds SLOT (every
// filling entry as [Cred]: Name, Placeholder, Hosts, Host), host SLOT, param
// NAME, path REL (absolute path in the profile's session directory), dir,
// cabundle (the session CA bundle), home, scrim (the scrim executable,
// Session.Scrim), authsjson SLOT USER [HELPER] (a container registry auth
// file, with credHelpers naming HELPER), b64, basic USER PASS, json, shquote,
// envname, stripport. A
// variable whose template renders empty is not set, unless the template
// itself is empty. Templates only ever see placeholders.
//
// # API
//
//	set, err := profiles.Load(cfg)           // built-ins + configuration
//	chosen, err := set.Select(profiles.Enabled.Get(cfg), cat) // run.profiles, "auto", "none"
//	r, err := profiles.Render(chosen.Profiles, cat, profiles.Session{
//		Dir: sessionDir + "/profiles", CABundle: bundle, Home: home})
//	err = r.Write(sess.Dir)                  // 0700 dirs, 0600 files
//	env = profiles.Apply(environ, r)         // unset, then set
//
// [Rendered] carries Env (name, value, profile), Unset (a trailing * is a
// prefix; test with [Unsets]), Files (paths relative to Session.Dir), Dirs,
// Hosts per profile and Warnings. `scrim run` applies it through
// run.Options.Profiles: variables scrim run sets itself win, files go under
// <session-dir>/profiles and are removed with the session directory.
//
// Rendered.Paths lists, per applied profile, the fixed home-directory
// credential paths the tool reads when no override variable is set
// (~/.aws/credentials, ~/.kube/config, ~/.docker/config.json, ...), with the
// absolute path of the generated replacement or "" to hide the path. The
// session filesystem view (10a.7, 10a.8) mounts or mirrors these.
//
// The git, docker, aws and kubectl profiles point their tools at scrim's
// credential helpers (internal/credhelper) when their `helper` param is
// "scrim": a git credential.helper, credHelpers in the docker config with
// docker-credential-scrim in [Rendered.Bin], a credential_process and a
// kubeconfig exec user. git and docker default to it.
//
// [Check] runs a profile's test command with an empty home, decoys at the
// fixed paths and in the unset variables, and fails unless the tool prints
// the generated placeholder and no decoy (`scrim profiles test`).
// [SampleBindings] fills every slot with a sample placeholder.
package profiles
