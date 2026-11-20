// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import "encoding/json"

// Wire models of the Bitwarden API. Every string that a Bitwarden client
// would show (names, notes, usernames, passwords, field names and values) is
// an EncString here. encoding/json matches field names case-insensitively,
// so these decode both the camelCase of current servers and the PascalCase
// of older Vaultwarden releases.

// Cipher types.
const (
	cipherLogin      = 1
	cipherSecureNote = 2
	cipherCard       = 3
	cipherIdentity   = 4
	cipherSSHKey     = 5
)

// Custom field types.
const (
	fieldText    = 0
	fieldHidden  = 1
	fieldBoolean = 2
	fieldLinked  = 3
)

type syncResponse struct {
	Profile     profileJSON      `json:"profile"`
	Folders     []folderJSON     `json:"folders"`
	Collections []collectionJSON `json:"collections"`
	Ciphers     []cipherJSON     `json:"ciphers"`
}

type profileJSON struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Key           string    `json:"key"`
	PrivateKey    string    `json:"privateKey"`
	Organizations []orgJSON `json:"organizations"`
}

type orgJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"` // plaintext: organisation names are not encrypted
	Key  string `json:"key"`  // org key wrapped for the user's public key
}

type folderJSON struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RevisionDate string `json:"revisionDate"`
}

type collectionJSON struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	ReadOnly       bool   `json:"readOnly"`
}

type fieldJSON struct {
	Type     int     `json:"type"`
	Name     *string `json:"name"`
	Value    *string `json:"value"`
	LinkedID *int    `json:"linkedId"`
}

type loginJSON struct {
	Username             *string         `json:"username"`
	Password             *string         `json:"password"`
	Totp                 *string         `json:"totp"`
	URIs                 json.RawMessage `json:"uris,omitempty"`
	PasswordRevisionDate *string         `json:"passwordRevisionDate,omitempty"`
	AutofillOnPageLoad   *bool           `json:"autofillOnPageLoad,omitempty"`
	Fido2Credentials     json.RawMessage `json:"fido2Credentials,omitempty"`
}

type cipherJSON struct {
	ID             string          `json:"id,omitempty"`
	OrganizationID *string         `json:"organizationId"`
	FolderID       *string         `json:"folderId"`
	Type           int             `json:"type"`
	Name           string          `json:"name"`
	Notes          *string         `json:"notes"`
	Key            *string         `json:"key"`
	Favorite       bool            `json:"favorite"`
	Reprompt       int             `json:"reprompt"`
	Login          *loginJSON      `json:"login"`
	SecureNote     json.RawMessage `json:"secureNote,omitempty"`
	Card           json.RawMessage `json:"card,omitempty"`
	Identity       json.RawMessage `json:"identity,omitempty"`
	SSHKey         json.RawMessage `json:"sshKey,omitempty"`
	Fields         []fieldJSON     `json:"fields"`
	PasswordHist   json.RawMessage `json:"passwordHistory,omitempty"`
	CollectionIDs  []string        `json:"collectionIds,omitempty"`
	RevisionDate   string          `json:"revisionDate,omitempty"`
	CreationDate   string          `json:"creationDate,omitempty"`
	DeletedDate    *string         `json:"deletedDate,omitempty"`
}

// cipherRequest is the body of create and update calls: a cipher plus the
// revision date the client last saw, which the server uses to refuse lost
// updates.
type cipherRequest struct {
	cipherJSON
	LastKnownRevisionDate *string
	// EncryptedFor is the id of the user whose keys encrypted the cipher.
	// Current servers refuse writes without it.
	EncryptedFor string
}

// MarshalJSON flattens the embedded cipher and drops response-only fields.
func (r *cipherRequest) MarshalJSON() ([]byte, error) {
	c := r.cipherJSON
	c.ID, c.RevisionDate, c.CreationDate, c.DeletedDate, c.CollectionIDs = "", "", "", nil, nil
	type plain cipherJSON
	b, err := json.Marshal(plain(c))
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	lk, _ := json.Marshal(r.LastKnownRevisionDate)
	m["lastKnownRevisionDate"] = lk
	ef, _ := json.Marshal(r.EncryptedFor)
	m["encryptedFor"] = ef
	return json.Marshal(m)
}
