// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
)

// ToolDatabaseQuery is the read-only database tool's name, as MCP tool and
// audit action (tool.database_query).
const ToolDatabaseQuery = "database_query"

// DatabaseQueryInput is one call of the read-only database tool. No field
// holds a value: placeholders inside SQL string literals and in Params stand
// for them, and scrim binds the real values as parameters.
type DatabaseQueryInput struct {
	Database string   `json:"database" jsonschema:"name of a configured database (see database_list)"`
	SQL      string   `json:"sql" jsonschema:"one read statement (SELECT, WITH, VALUES, TABLE, SHOW, EXPLAIN); a placeholder inside a string literal is bound as a parameter"`
	Params   []string `json:"params,omitempty" jsonschema:"values for $1, $2 (PostgreSQL) or ? (MySQL), in order; each may contain placeholders"`
	MaxRows  int      `json:"max_rows,omitempty" jsonschema:"return at most this many rows, below the database's limit"`
}

// DatabaseQueryOutput is the tool's answer. Its cells passed scrim's
// redactor and guard: known values are placeholders.
type DatabaseQueryOutput struct {
	Database  string      `json:"database"`
	Columns   []string    `json:"columns"`
	Rows      [][]*string `json:"rows"`
	Truncated bool        `json:"truncated,omitempty"`
	// Replacements counts the values the redactor replaced in the result.
	Replacements int `json:"replacements,omitempty"`
}

// DatabaseInfo describes one configured database. No credential.
type DatabaseInfo struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Listen string `json:"listen"`
	Tool   bool   `json:"tool"`
}

// DatabaseListOutput is the answer of GET /v1/databases.
type DatabaseListOutput struct {
	Databases []DatabaseInfo `json:"databases"`
}

// Databases serves the read-only database tool. Query owns policy, binding
// and redaction; an error it returns is an *agenttools.Error or becomes a
// generic one.
type Databases interface {
	List(ctx context.Context, id identity.Identity) (DatabaseListOutput, error)
	Query(ctx context.Context, id identity.Identity, in DatabaseQueryInput) (DatabaseQueryOutput, error)
}

func (s *Server) databaseList(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	if s.Databases == nil {
		writeJSON(w, http.StatusOK, DatabaseListOutput{Databases: []DatabaseInfo{}})
		return
	}
	out, err := s.Databases.List(r.Context(), id)
	reply(w, out, err)
}

func (s *Server) databaseQuery(w http.ResponseWriter, r *http.Request, id identity.Identity) {
	if s.Databases == nil {
		writeError(w, agenttools.Errorf(agenttools.CodeNotFound, "no databases are configured in this scrim process"))
		return
	}
	var in DatabaseQueryInput
	if !decode(w, r, &in) {
		return
	}
	entry := agenttools.AuditEntry{Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source), SessionID: id.SessionID,
		UID: id.Peer.UID, PID: id.Peer.PID, Tool: ToolDatabaseQuery, Ref: "database:" + in.Database}
	out, err := s.Databases.Query(r.Context(), id, in)
	if err != nil {
		e := agenttools.Public(err)
		entry.Outcome, entry.Detail = agenttools.OutcomeError, string(e.Code)+": "+e.Message
		if e.Code == agenttools.CodeDenied || e.Code == agenttools.CodeForbidden {
			entry.Outcome = agenttools.OutcomeDenied
		}
		s.audit(r.Context(), entry)
		writeError(w, e)
		return
	}
	entry.Outcome = agenttools.OutcomeOK
	entry.Detail = strconv.Itoa(len(out.Rows)) + " rows"
	if out.Replacements > 0 {
		entry.Detail += ", " + strconv.Itoa(out.Replacements) + " values replaced"
	}
	s.audit(r.Context(), entry)
	writeJSON(w, http.StatusOK, out)
}

// DatabaseList calls database_list.
func (c *Client) DatabaseList(ctx context.Context) (DatabaseListOutput, error) {
	var out DatabaseListOutput
	return out, c.do(ctx, http.MethodGet, "/databases", nil, nil, "", &out)
}

// DatabaseQuery calls database_query.
func (c *Client) DatabaseQuery(ctx context.Context, in DatabaseQueryInput) (DatabaseQueryOutput, error) {
	var out DatabaseQueryOutput
	return out, c.json(ctx, http.MethodPost, "/databases/query", in, &out)
}
