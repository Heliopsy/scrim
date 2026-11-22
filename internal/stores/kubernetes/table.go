// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/heliopsy/scrim/internal/stores"
)

// Server-side tables (the form `kubectl get` uses) give a Secret's metadata
// and its type without its data: the table for Secrets has the columns
// Name, Type, Data (the number of keys) and Age, and includeObject=Metadata
// adds each row's PartialObjectMetadata. The metadata API alone would not
// do: type is not part of an object's metadata.

const tableAccept = "application/json;as=Table;v=v1;g=meta.k8s.io"

// row is one Secret from a table.
type row struct {
	meta metav1.ObjectMeta
	typ  string
}

// errTable is a table the adapter cannot read.
var errTable = errors.New("unexpected table from the API server")

// table fetches the table of Secret name in ns, or of every Secret in ns
// when name is empty (one page from cont, with the next page's token).
func (a *Adapter) table(ctx context.Context, c *Clients, ns, name, cont string) ([]row, string, error) {
	req := c.REST.Get().Namespace(ns).Resource("secrets").
		SetHeader("Accept", tableAccept).
		Param("includeObject", "Metadata")
	if name != "" {
		req = req.Name(name)
	} else {
		req = req.Param("limit", strconv.Itoa(listPage))
		if cont != "" {
			req = req.Param("continue", cont)
		}
	}
	raw, err := req.DoRaw(ctx)
	if err != nil {
		return nil, "", err
	}
	var t metav1.Table
	if err := json.Unmarshal(raw, &t); err != nil || t.Kind != "Table" {
		return nil, "", errTable
	}
	col := -1
	for i, d := range t.ColumnDefinitions {
		if d.Name == "Type" {
			col = i
		}
	}
	if col < 0 {
		return nil, "", errTable
	}
	out := make([]row, 0, len(t.Rows))
	for _, r := range t.Rows {
		var pm metav1.PartialObjectMetadata
		if len(r.Object.Raw) == 0 || json.Unmarshal(r.Object.Raw, &pm) != nil || pm.Name == "" || col >= len(r.Cells) {
			return nil, "", errTable
		}
		typ, _ := r.Cells[col].(string)
		out = append(out, row{meta: pm.ObjectMeta, typ: typ})
	}
	return out, t.Continue, nil
}

// listPage is how many Secrets one table page holds.
const listPage = 500

func (a *Adapter) tableErr(op stores.Op, ref stores.Ref, err error) error {
	if errors.Is(err, errTable) {
		return a.err(op, ref, stores.ErrUnavailable, err.Error())
	}
	return a.apiErr(op, ref, err)
}
