package bitwarden

import (
	"context"
	"net/http"
	"net/url"
)

func (c *Client) apiCall(ctx context.Context, op, method, path string, body, out any) error {
	return c.do(ctx, request{
		op:     op,
		method: method,
		url:    c.api + path,
		body:   body,
		auth:   true,
		out:    out,
	})
}

func esc(s string) string { return url.PathEscape(s) }

// Sync returns everything the account can see, encrypted.
func (c *Client) Sync(ctx context.Context) (*SyncResponse, error) {
	var out SyncResponse
	if err := c.apiCall(ctx, "sync", http.MethodGet, "/sync?excludeDomains=true", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateCipher stores a new item. An organization item must name at least
// one collection.
func (c *Client) CreateCipher(ctx context.Context, cipher Cipher, collectionIDs []string) (*Cipher, error) {
	var out Cipher
	if cipher.OrganizationID == nil {
		err := c.apiCall(ctx, "create_cipher", http.MethodPost, "/ciphers", cipher, &out)
		if err != nil {
			return nil, err
		}
		return &out, nil
	}
	body := struct {
		Cipher        Cipher   `json:"cipher"`
		CollectionIDs []string `json:"collectionIds"`
	}{cipher, collectionIDs}
	if err := c.apiCall(ctx, "create_cipher", http.MethodPost, "/ciphers/create", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateCipher replaces an item. Set LastKnownRevisionDate to refuse the write
// when the item changed since it was read.
func (c *Client) UpdateCipher(ctx context.Context, id string, cipher Cipher) (*Cipher, error) {
	var out Cipher
	if err := c.apiCall(ctx, "update_cipher", http.MethodPut, "/ciphers/"+esc(id), cipher, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetCipherCollections replaces the collections an organization item is in.
func (c *Client) SetCipherCollections(ctx context.Context, id string, collectionIDs []string) error {
	body := map[string][]string{"collectionIds": collectionIDs}
	return c.apiCall(ctx, "set_cipher_collections", http.MethodPut, "/ciphers/"+esc(id)+"/collections", body, nil)
}

// TrashCipher moves an item to the trash, from which it can be restored.
func (c *Client) TrashCipher(ctx context.Context, id string) error {
	return c.apiCall(ctx, "trash_cipher", http.MethodPut, "/ciphers/"+esc(id)+"/delete", nil, nil)
}

// DeleteCipher destroys an item permanently.
func (c *Client) DeleteCipher(ctx context.Context, id string) error {
	return c.apiCall(ctx, "delete_cipher", http.MethodDelete, "/ciphers/"+esc(id), nil, nil)
}

// RestoreCipher brings an item back from the trash.
func (c *Client) RestoreCipher(ctx context.Context, id string) (*Cipher, error) {
	var out Cipher
	if err := c.apiCall(ctx, "restore_cipher", http.MethodPut, "/ciphers/"+esc(id)+"/restore", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// NewAttachment describes a file about to be uploaded.
type NewAttachment struct {
	Key          string `json:"key"`
	FileName     string `json:"fileName"`
	FileSize     int64  `json:"fileSize"`
	AdminRequest bool   `json:"adminRequest"`
}

type attachmentSlot struct {
	AttachmentID   string `json:"attachmentId"`
	URL            string `json:"url"`
	FileUploadType int    `json:"fileUploadType"`
}

// AttachmentSlot is a registered attachment waiting for its content.
type AttachmentSlot struct {
	ID  string
	url string
}

// CreateAttachment registers an attachment. The item shows it from this moment,
// so a caller whose upload then fails must delete the slot.
func (c *Client) CreateAttachment(ctx context.Context, cipherID string, meta NewAttachment) (AttachmentSlot, error) {
	var slot attachmentSlot
	err := c.apiCall(ctx, "attachment_create", http.MethodPost, "/ciphers/"+esc(cipherID)+"/attachment/v2", meta, &slot)
	if err != nil {
		return AttachmentSlot{}, err
	}
	target, err := c.resolve(slot.URL, c.api)
	if err != nil {
		return AttachmentSlot{}, err
	}
	return AttachmentSlot{ID: slot.AttachmentID, url: target}, nil
}

// UploadAttachment sends the encrypted content of a registered attachment.
func (c *Client) UploadAttachment(ctx context.Context, slot AttachmentSlot, encryptedFileName string, content []byte) error {
	return c.upload(ctx, "attachment_upload", slot.url, "data", encryptedFileName, content)
}

// AttachmentContent downloads the encrypted content of an attachment.
func (c *Client) AttachmentContent(ctx context.Context, cipherID, attachmentID string, limit int64) ([]byte, error) {
	var meta Attachment
	path := "/ciphers/" + esc(cipherID) + "/attachment/" + esc(attachmentID)
	if err := c.apiCall(ctx, "attachment_meta", http.MethodGet, path, nil, &meta); err != nil {
		return nil, err
	}
	target, err := c.resolve(meta.URL, c.base.String())
	if err != nil {
		return nil, err
	}
	return c.download(ctx, "attachment_download", target, limit)
}

// DeleteAttachment removes an attachment.
func (c *Client) DeleteAttachment(ctx context.Context, cipherID, attachmentID string) error {
	path := "/ciphers/" + esc(cipherID) + "/attachment/" + esc(attachmentID)
	return c.apiCall(ctx, "attachment_delete", http.MethodDelete, path, nil, nil)
}

// CollectionRequest creates or updates a collection.
type CollectionRequest struct {
	Name       string  `json:"name"`
	ExternalID *string `json:"externalId"`
	// Groups is sent back unchanged on update: the server replaces a
	// collection's group grants with whatever the request holds.
	Groups []CollectionAccess `json:"groups"`
	Users  []CollectionAccess `json:"users"`
}

// OrgCollections lists every collection of the organization with its members.
// It needs a role that manages collections.
func (c *Client) OrgCollections(ctx context.Context, orgID string) ([]CollectionDetails, error) {
	var out struct {
		Data []CollectionDetails `json:"data"`
	}
	path := "/organizations/" + esc(orgID) + "/collections/details"
	if err := c.apiCall(ctx, "org_collections", http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// CreateCollection adds a collection to the organization.
func (c *Client) CreateCollection(ctx context.Context, orgID string, req CollectionRequest) (*Collection, error) {
	var out Collection
	path := "/organizations/" + esc(orgID) + "/collections"
	if err := c.apiCall(ctx, "create_collection", http.MethodPost, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateCollection replaces a collection's name and member access.
func (c *Client) UpdateCollection(ctx context.Context, orgID, id string, req CollectionRequest) (*Collection, error) {
	var out Collection
	path := "/organizations/" + esc(orgID) + "/collections/" + esc(id)
	if err := c.apiCall(ctx, "update_collection", http.MethodPut, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteCollection removes a collection. Items stay in the organization.
func (c *Client) DeleteCollection(ctx context.Context, orgID, id string) error {
	path := "/organizations/" + esc(orgID) + "/collections/" + esc(id)
	return c.apiCall(ctx, "delete_collection", http.MethodDelete, path, nil, nil)
}

// Members lists the organization's memberships with their collection access.
func (c *Client) Members(ctx context.Context, orgID string) ([]Member, error) {
	var out struct {
		Data []Member `json:"data"`
	}
	path := "/organizations/" + esc(orgID) + "/users?includeCollections=true&includeGroups=true"
	if err := c.apiCall(ctx, "members", http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// MemberRequest invites or updates a member. Groups and permissions are always
// sent — Vaultwarden rejects the request without them — and an update sends the
// member's current groups back, because the server replaces them wholesale.
type MemberRequest struct {
	Emails               []string           `json:"emails,omitempty"`
	Type                 MemberType         `json:"type"`
	AccessAll            bool               `json:"accessAll"`
	Collections          []CollectionAccess `json:"collections"`
	Groups               []string           `json:"groups"`
	Permissions          map[string]bool    `json:"permissions"`
	AccessSecretsManager bool               `json:"accessSecretsManager"`
}

// InviteMembers sends invitations.
func (c *Client) InviteMembers(ctx context.Context, orgID string, req MemberRequest) error {
	path := "/organizations/" + esc(orgID) + "/users/invite"
	return c.apiCall(ctx, "invite_members", http.MethodPost, path, req, nil)
}

// UpdateMember changes a member's role and collection access.
func (c *Client) UpdateMember(ctx context.Context, orgID, memberID string, req MemberRequest) error {
	path := "/organizations/" + esc(orgID) + "/users/" + esc(memberID)
	return c.apiCall(ctx, "update_member", http.MethodPut, path, req, nil)
}

// ConfirmMember completes a membership by handing the member the organization
// key, wrapped with the member's public key.
func (c *Client) ConfirmMember(ctx context.Context, orgID, memberID, wrappedKey string) error {
	path := "/organizations/" + esc(orgID) + "/users/" + esc(memberID) + "/confirm"
	return c.apiCall(ctx, "confirm_member", http.MethodPost, path, map[string]string{"key": wrappedKey}, nil)
}

// RevokeMember suspends a membership without removing it.
func (c *Client) RevokeMember(ctx context.Context, orgID, memberID string) error {
	path := "/organizations/" + esc(orgID) + "/users/" + esc(memberID) + "/revoke"
	return c.apiCall(ctx, "revoke_member", http.MethodPut, path, nil, nil)
}

// RestoreMember lifts a revocation.
func (c *Client) RestoreMember(ctx context.Context, orgID, memberID string) error {
	path := "/organizations/" + esc(orgID) + "/users/" + esc(memberID) + "/restore"
	return c.apiCall(ctx, "restore_member", http.MethodPut, path, nil, nil)
}

// RemoveMember deletes a membership.
func (c *Client) RemoveMember(ctx context.Context, orgID, memberID string) error {
	path := "/organizations/" + esc(orgID) + "/users/" + esc(memberID)
	return c.apiCall(ctx, "remove_member", http.MethodDelete, path, nil, nil)
}

// UserPublicKey returns an account's public key.
func (c *Client) UserPublicKey(ctx context.Context, userID string) (string, error) {
	var out struct {
		PublicKey string `json:"publicKey"`
	}
	if err := c.apiCall(ctx, "user_public_key", http.MethodGet, "/users/"+esc(userID)+"/public-key", nil, &out); err != nil {
		return "", err
	}
	return out.PublicKey, nil
}

// Events reads the organization event log between two RFC 3339 timestamps,
// one page at a time.
func (c *Client) Events(ctx context.Context, orgID, start, end, continuation string) ([]Event, string, error) {
	q := url.Values{"start": {start}, "end": {end}}
	if continuation != "" {
		q.Set("continuationToken", continuation)
	}
	var out struct {
		Data              []Event `json:"data"`
		ContinuationToken *string `json:"continuationToken"`
	}
	path := "/organizations/" + esc(orgID) + "/events?" + q.Encode()
	if err := c.apiCall(ctx, "events", http.MethodGet, path, nil, &out); err != nil {
		return nil, "", err
	}
	next := ""
	if out.ContinuationToken != nil {
		next = *out.ContinuationToken
	}
	return out.Data, next, nil
}

// CreateSend stores a Send.
func (c *Client) CreateSend(ctx context.Context, send Send) (*Send, error) {
	var out Send
	if err := c.apiCall(ctx, "create_send", http.MethodPost, "/sends", send, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSend removes a Send, which disables its link immediately.
func (c *Client) DeleteSend(ctx context.Context, id string) error {
	return c.apiCall(ctx, "delete_send", http.MethodDelete, "/sends/"+esc(id), nil, nil)
}

// OrganizationRequest creates an organization. Provisioning and tests only.
type OrganizationRequest struct {
	Name           string              `json:"name"`
	BillingEmail   string              `json:"billingEmail"`
	PlanType       int                 `json:"planType"`
	Key            string              `json:"key"`
	Keys           RegistrationKeyPair `json:"keys"`
	CollectionName string              `json:"collectionName"`
}

// CreateOrganization creates an organization owned by the account.
func (c *Client) CreateOrganization(ctx context.Context, req OrganizationRequest) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.apiCall(ctx, "create_organization", http.MethodPost, "/organizations", req, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// APIKey returns the account's personal API key secret. Provisioning and
// tests only.
func (c *Client) APIKey(ctx context.Context, passwordHash string) (string, error) {
	var out struct {
		APIKey string `json:"apiKey"`
	}
	body := map[string]string{"masterPasswordHash": passwordHash}
	if err := c.apiCall(ctx, "api_key", http.MethodPost, "/accounts/api-key", body, &out); err != nil {
		return "", err
	}
	return out.APIKey, nil
}

// AcceptInvite accepts an organization invitation with the token from the
// invitation email. Provisioning and tests only.
func (c *Client) AcceptInvite(ctx context.Context, orgID, memberID, token string) error {
	path := "/organizations/" + esc(orgID) + "/users/" + esc(memberID) + "/accept"
	return c.apiCall(ctx, "accept_invite", http.MethodPost, path, map[string]string{"token": token}, nil)
}
