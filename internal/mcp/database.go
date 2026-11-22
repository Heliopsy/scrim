// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/heliopsy/scrim/internal/localapi"
)

// DatabaseAPI is the read-only database tool. The local API client
// implements it; an API without it serves no database tools.
type DatabaseAPI interface {
	DatabaseList(ctx context.Context) (localapi.DatabaseListOutput, error)
	DatabaseQuery(ctx context.Context, in localapi.DatabaseQueryInput) (localapi.DatabaseQueryOutput, error)
}

// DatabaseListInput is database_list, which takes no arguments.
type DatabaseListInput struct{}

func addDatabaseTools(srv *sdk.Server, api DatabaseAPI) {
	read := &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}
	sdk.AddTool(srv, &sdk.Tool{Name: "database_list", Annotations: read,
		Description: "List the databases scrim can query for you and their local proxy endpoints. No credentials."},
		handle(func(ctx context.Context, _ DatabaseListInput) (localapi.DatabaseListOutput, error) {
			return api.DatabaseList(ctx)
		}))
	sdk.AddTool(srv, &sdk.Tool{Name: localapi.ToolDatabaseQuery, Annotations: read,
		Description: "Run one read-only SQL statement on a configured database. Put a placeholder (such as a secret's " +
			"⟦scrim:...⟧) inside a string literal or in params and scrim binds the real value as a query parameter; you " +
			"never see it. Writes, DDL and multiple statements are refused, the statement runs in a read-only transaction " +
			"with a timeout and a row limit, and known secret values in the result come back as placeholders."},
		handle(func(ctx context.Context, in localapi.DatabaseQueryInput) (localapi.DatabaseQueryOutput, error) {
			return api.DatabaseQuery(ctx, in)
		}))
}
