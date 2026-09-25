// Package fakevw is an in-memory stand-in for a Vaultwarden server, for tests
// that must run without Docker. It stores what clients send — encrypted
// strings it cannot read, as the real server does — and reproduces the
// behaviour the integration suite verified against Vaultwarden 1.36: visibility
// by membership and collection, revision checks on update, the attachment
// upload flow, invitations auto-accepted for existing accounts, confirmation.
package fakevw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/keys"
)

// Account is a provisioned account and the credentials a client logs in with.
type Account struct {
	ID           string
	Email        string
	Password     string
	ClientID     string
	ClientSecret string
	key          string
	privateKey   string
	publicKey    string
	private      keys.PrivateKey
	userKey      keys.SymmetricKey
}

type member struct {
	id          string
	userID      string
	email       string
	status      bitwarden.MemberStatus
	role        bitwarden.MemberType
	key         string
	collections []bitwarden.CollectionAccess
	// accessAll is a manager of every collection.
	accessAll bool
}

type organization struct {
	id      string
	name    string
	key     keys.SymmetricKey
	members []*member
}

type collection struct {
	id    string
	orgID string
	name  string
}

type cipher struct {
	c     bitwarden.Cipher
	owner string // user id for personal items
	files map[string][]byte
}

// Server is the fake.
type Server struct {
	t   *testing.T
	srv *httptest.Server
	now func() time.Time

	mu          sync.Mutex
	accounts    map[string]*Account // by id
	tokens      map[string]string   // access token -> account id
	orgs        map[string]*organization
	collections map[string]*collection
	ciphers     map[string]*cipher
	sends       map[string]bitwarden.Send
	sendOwner   map[string]string
	events      []bitwarden.Event
	// failSyncIn counts down syncs until one answers 500; zero is off.
	failSyncIn int
	// failUpload makes the next attachment upload fail.
	failUpload bool
	// panel is the admin panel; nil until EnableAdmin.
	panel *panel
}

// New starts a fake server; it stops with the test.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		t: t, now: time.Now,
		accounts: map[string]*Account{}, tokens: map[string]string{}, orgs: map[string]*organization{},
		collections: map[string]*collection{}, ciphers: map[string]*cipher{}, sends: map[string]bitwarden.Send{},
		sendOwner: map[string]string{},
	}
	s.srv = httptest.NewServer(s.routes())
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the server root.
func (s *Server) URL() string { return s.srv.URL }

// FailSync makes the nth sync from now answer 500 (1 is the next one).
func (s *Server) FailSync(nth int) {
	s.mu.Lock()
	s.failSyncIn = nth
	s.mu.Unlock()
}

// FailNextUpload makes the next attachment upload answer 500.
func (s *Server) FailNextUpload() {
	s.mu.Lock()
	s.failUpload = true
	s.mu.Unlock()
}

// Attachments counts the attachments an item has on the server.
func (s *Server) Attachments(itemID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.ciphers[itemID]; c != nil {
		return len(c.c.Attachments)
	}
	return 0
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails since Go 1.24: it crashes the process instead
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (s *Server) must(err error) {
	s.t.Helper()
	if err != nil {
		s.t.Fatal(err)
	}
}

// AddAccount provisions an account the way a client registers one.
func (s *Server) AddAccount(email, password string) *Account {
	s.t.Helper()
	kdf := keys.KDF{Type: keys.KDFPBKDF2, Iterations: 5000}
	master, err := keys.MasterKey(password, email, kdf)
	s.must(err)
	stretched, err := keys.StretchMasterKey(master)
	s.must(err)
	userKey, err := keys.GenerateSymmetricKey()
	s.must(err)
	wrapped, err := stretched.EncryptKey(userKey)
	s.must(err)
	private, err := keys.GeneratePrivateKey()
	s.must(err)
	der, err := private.PKCS8()
	s.must(err)
	encPrivate, err := userKey.Encrypt(der)
	s.must(err)
	public, err := private.PublicSPKI()
	s.must(err)
	id := newID()
	a := &Account{
		ID: id, Email: email, Password: password, ClientID: "user." + id, ClientSecret: newID(),
		key: wrapped, privateKey: encPrivate.String(), publicKey: public, private: private, userKey: userKey,
	}
	s.mu.Lock()
	s.accounts[id] = a
	s.mu.Unlock()
	return a
}

// AddOrganization creates an organization owned by the account, with named
// collections. It returns the organization id and collection ids by name.
func (s *Server) AddOrganization(owner *Account, name string, collections ...string) (string, map[string]string) {
	s.t.Helper()
	orgKey, err := keys.GenerateSymmetricKey()
	s.must(err)
	wrapped, err := owner.private.Public().EncryptKey(orgKey)
	s.must(err)
	org := &organization{id: newID(), name: name, key: orgKey}
	org.members = append(org.members, &member{id: newID(), userID: owner.ID, email: owner.Email, status: bitwarden.MemberConfirmed, role: bitwarden.MemberOwner, key: wrapped})
	ids := map[string]string{}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[org.id] = org
	for _, c := range collections {
		enc, err := orgKey.EncryptString(c)
		s.must(err)
		col := &collection{id: newID(), orgID: org.id, name: enc}
		s.collections[col.id] = col
		ids[c] = col.id
	}
	return org.id, ids
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": msg, "errorModel": map[string]string{"message": msg}})
}

func decode(r *http.Request, v any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// authed wraps a handler with bearer authentication.
func (s *Server) authed(h func(w http.ResponseWriter, r *http.Request, a *Account)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		id, ok := s.tokens[token]
		a := s.accounts[id]
		s.mu.Unlock()
		if !ok {
			fail(w, http.StatusUnauthorized, "invalid token")
			return
		}
		h(w, r, a)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	s.adminRoutes(mux)
	mux.HandleFunc("POST /identity/connect/token", s.token)
	mux.HandleFunc("GET /api/sync", s.authed(s.sync))
	mux.HandleFunc("POST /api/ciphers/create", s.authed(s.createCipher))
	mux.HandleFunc("PUT /api/ciphers/{id}", s.authed(s.updateCipher))
	mux.HandleFunc("PUT /api/ciphers/{id}/collections", s.authed(s.setCollections))
	mux.HandleFunc("PUT /api/ciphers/{id}/delete", s.authed(s.trashCipher))
	mux.HandleFunc("PUT /api/ciphers/{id}/restore", s.authed(s.restoreCipher))
	mux.HandleFunc("DELETE /api/ciphers/{id}", s.authed(s.deleteCipher))
	mux.HandleFunc("POST /api/ciphers/{id}/attachment/v2", s.authed(s.attachmentSlot))
	mux.HandleFunc("POST /api/ciphers/{id}/attachment/{aid}", s.authed(s.attachmentUpload))
	mux.HandleFunc("GET /api/ciphers/{id}/attachment/{aid}", s.authed(s.attachmentMeta))
	mux.HandleFunc("DELETE /api/ciphers/{id}/attachment/{aid}", s.authed(s.attachmentDelete))
	mux.HandleFunc("GET /attachments/{id}/{aid}", s.attachmentFile)
	mux.HandleFunc("POST /api/sends", s.authed(s.createSend))
	mux.HandleFunc("DELETE /api/sends/{id}", s.authed(s.deleteSend))
	mux.HandleFunc("GET /api/organizations/{org}/collections/details", s.authed(s.orgCollections))
	mux.HandleFunc("POST /api/organizations/{org}/collections", s.authed(s.createCollection))
	mux.HandleFunc("PUT /api/organizations/{org}/collections/{id}", s.authed(s.updateCollection))
	mux.HandleFunc("DELETE /api/organizations/{org}/collections/{id}", s.authed(s.deleteCollection))
	mux.HandleFunc("GET /api/organizations/{org}/users", s.authed(s.members))
	mux.HandleFunc("POST /api/organizations/{org}/users/invite", s.authed(s.invite))
	mux.HandleFunc("PUT /api/organizations/{org}/users/{id}", s.authed(s.updateMember))
	mux.HandleFunc("POST /api/organizations/{org}/users/{id}/confirm", s.authed(s.confirm))
	mux.HandleFunc("PUT /api/organizations/{org}/users/{id}/revoke", s.authed(s.memberStatus(bitwarden.MemberRevoked)))
	mux.HandleFunc("PUT /api/organizations/{org}/users/{id}/restore", s.authed(s.memberStatus(bitwarden.MemberConfirmed)))
	mux.HandleFunc("DELETE /api/organizations/{org}/users/{id}", s.authed(s.removeMember))
	mux.HandleFunc("GET /api/users/{id}/public-key", s.authed(s.publicKey))
	mux.HandleFunc("GET /api/organizations/{org}/events", s.authed(s.orgEvents))
	return mux
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("deviceIdentifier") == "" {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.ClientID == r.PostForm.Get("client_id") && a.ClientSecret == r.PostForm.Get("client_secret") {
			token := newID()
			s.tokens[token] = a.ID
			writeJSON(w, map[string]any{
				"access_token": token, "expires_in": 7200, "token_type": "Bearer",
				"Key": a.key, "PrivateKey": a.privateKey, "Kdf": 0, "KdfIterations": 5000,
				"UserDecryptionOptions": map[string]any{"MasterPasswordUnlock": map[string]any{"Salt": a.Email}},
			})
			return
		}
	}
	fail(w, http.StatusBadRequest, "invalid_client")
}

// membership returns the account's confirmed membership of an organization.
func (s *Server) membership(orgID, userID string) *member {
	org := s.orgs[orgID]
	if org == nil {
		return nil
	}
	for _, m := range org.members {
		if m.userID == userID {
			return m
		}
	}
	return nil
}

func manages(m *member) bool {
	return m != nil && m.status == bitwarden.MemberConfirmed && (m.role == bitwarden.MemberOwner || m.role == bitwarden.MemberAdmin)
}

// access returns the account's grant on a collection, or nil.
func (s *Server) access(colID, userID string) *bitwarden.CollectionAccess {
	col := s.collections[colID]
	if col == nil {
		return nil
	}
	m := s.membership(col.orgID, userID)
	if m == nil || m.status != bitwarden.MemberConfirmed {
		return nil
	}
	if manages(m) {
		return &bitwarden.CollectionAccess{ID: colID, Manage: true}
	}
	for i := range m.collections {
		if m.collections[i].ID == colID {
			return &m.collections[i]
		}
	}
	return nil
}

// view returns the cipher as the account sees it, or false when hidden.
func (s *Server) view(c *cipher, userID string) (bitwarden.Cipher, bool) {
	out := c.c
	if c.c.OrganizationID == nil {
		out.Edit, out.ViewPassword = true, true
		return out, c.owner == userID
	}
	if manages(s.membership(*c.c.OrganizationID, userID)) {
		out.Edit, out.ViewPassword = true, true
		return out, true
	}
	visible := false
	for _, id := range c.c.CollectionIDs {
		if a := s.access(id, userID); a != nil {
			visible = true
			out.Edit = out.Edit || !a.ReadOnly
			out.ViewPassword = out.ViewPassword || !a.HidePasswords
		}
	}
	return out, visible
}

func (s *Server) sync(w http.ResponseWriter, _ *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSyncIn > 0 {
		s.failSyncIn--
		if s.failSyncIn == 0 {
			fail(w, http.StatusInternalServerError, "sync failed")
			return
		}
	}
	resp := bitwarden.SyncResponse{Profile: bitwarden.Profile{ID: a.ID, Email: a.Email, Key: a.key, PrivateKey: a.privateKey}}
	for _, org := range s.orgs {
		if m := s.membership(org.id, a.ID); m != nil && m.status != bitwarden.MemberRevoked {
			resp.Profile.Organizations = append(resp.Profile.Organizations, bitwarden.Organization{ID: org.id, Name: org.name, Key: m.key, Type: m.role, Status: m.status, Enabled: true})
		}
	}
	for _, col := range s.collections {
		if acc := s.access(col.id, a.ID); acc != nil {
			resp.Collections = append(resp.Collections, bitwarden.Collection{ID: col.id, OrganizationID: col.orgID, Name: col.name, ReadOnly: acc.ReadOnly, HidePasswords: acc.HidePasswords, Manage: acc.Manage})
		}
	}
	for _, c := range s.ciphers {
		if v, ok := s.view(c, a.ID); ok {
			resp.Ciphers = append(resp.Ciphers, v)
		}
	}
	for id, send := range s.sends {
		if s.sendOwner[id] == a.ID {
			resp.Sends = append(resp.Sends, send)
		}
	}
	writeJSON(w, resp)
}

func (s *Server) stamp() string { return bitwarden.FormatTime(s.now()) }

func (s *Server) event(t int, actor string, cipherID, collectionID *string) {
	s.events = append(s.events, bitwarden.Event{Type: t, ActingUserID: &actor, CipherID: cipherID, CollectionID: collectionID, Date: s.stamp()})
}

func (s *Server) createCipher(w http.ResponseWriter, r *http.Request, a *Account) {
	var body struct {
		Cipher        bitwarden.Cipher `json:"cipher"`
		CollectionIDs []string         `json:"collectionIds"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if body.Cipher.OrganizationID == nil || len(body.CollectionIDs) == 0 {
		fail(w, http.StatusBadRequest, "You must select at least one collection.")
		return
	}
	for _, id := range body.CollectionIDs {
		acc := s.access(id, a.ID)
		if acc == nil || acc.ReadOnly || s.collections[id].orgID != *body.Cipher.OrganizationID {
			fail(w, http.StatusBadRequest, "You don't have permission to add an item to the submitted collection.")
			return
		}
	}
	c := body.Cipher
	c.ID, c.CollectionIDs = newID(), slices.Clone(body.CollectionIDs)
	c.CreationDate, c.RevisionDate = s.stamp(), s.stamp()
	c.LastKnownRevisionDate = ""
	s.ciphers[c.ID] = &cipher{c: c, files: map[string][]byte{}}
	s.event(1100, a.ID, &c.ID, nil)
	v, _ := s.view(s.ciphers[c.ID], a.ID)
	writeJSON(w, v)
}

// editable returns the cipher when the account may change it.
func (s *Server) editable(w http.ResponseWriter, id string, a *Account) *cipher {
	c := s.ciphers[id]
	if c == nil {
		fail(w, http.StatusNotFound, "Cipher doesn't exist")
		return nil
	}
	v, ok := s.view(c, a.ID)
	if !ok {
		fail(w, http.StatusNotFound, "Cipher doesn't exist")
		return nil
	}
	if !v.Edit {
		fail(w, http.StatusBadRequest, "Cipher is not write accessible")
		return nil
	}
	return c
}

func (s *Server) updateCipher(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.Cipher
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.editable(w, r.PathValue("id"), a)
	if c == nil {
		return
	}
	if body.LastKnownRevisionDate != "" && body.LastKnownRevisionDate != c.c.RevisionDate {
		fail(w, http.StatusBadRequest, "The client copy of this cipher is out of date. Resync the client and try again.")
		return
	}
	next := body
	next.ID, next.CollectionIDs, next.Attachments = c.c.ID, c.c.CollectionIDs, c.c.Attachments
	next.CreationDate, next.RevisionDate, next.OrganizationID = c.c.CreationDate, s.stamp(), c.c.OrganizationID
	next.LastKnownRevisionDate = ""
	c.c = next
	s.event(1101, a.ID, &next.ID, nil)
	v, _ := s.view(c, a.ID)
	writeJSON(w, v)
}

func (s *Server) setCollections(w http.ResponseWriter, r *http.Request, a *Account) {
	var body struct {
		CollectionIDs []string `json:"collectionIds"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.editable(w, r.PathValue("id"), a)
	if c == nil {
		return
	}
	c.c.CollectionIDs = slices.Clone(body.CollectionIDs)
	c.c.RevisionDate = s.stamp()
	s.event(1106, a.ID, &c.c.ID, nil)
}

func (s *Server) trashCipher(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.editable(w, r.PathValue("id"), a); c != nil {
		stamp := s.stamp()
		c.c.DeletedDate, c.c.RevisionDate = &stamp, stamp
		s.event(1115, a.ID, &c.c.ID, nil)
	}
}

func (s *Server) restoreCipher(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.editable(w, r.PathValue("id"), a); c != nil {
		c.c.DeletedDate, c.c.RevisionDate = nil, s.stamp()
		s.event(1116, a.ID, &c.c.ID, nil)
		v, _ := s.view(c, a.ID)
		writeJSON(w, v)
	}
}

func (s *Server) deleteCipher(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.editable(w, r.PathValue("id"), a); c != nil {
		delete(s.ciphers, c.c.ID)
		s.event(1102, a.ID, &c.c.ID, nil)
	}
}

func (s *Server) attachmentSlot(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.NewAttachment
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.editable(w, r.PathValue("id"), a)
	if c == nil {
		return
	}
	aid := newID()
	c.c.Attachments = append(c.c.Attachments, bitwarden.Attachment{ID: aid, FileName: body.FileName, Key: body.Key, Size: strconv.FormatInt(body.FileSize, 10)})
	writeJSON(w, map[string]any{"attachmentId": aid, "url": "/ciphers/" + c.c.ID + "/attachment/" + aid, "fileUploadType": 0})
}

func (s *Server) attachmentUpload(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	failing := s.failUpload
	s.failUpload = false
	s.mu.Unlock()
	if failing {
		fail(w, http.StatusInternalServerError, "upload failed")
		return
	}
	file, _, err := r.FormFile("data")
	if err != nil {
		fail(w, http.StatusBadRequest, "no data")
		return
	}
	data, err := io.ReadAll(file)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.editable(w, r.PathValue("id"), a); c != nil {
		c.files[r.PathValue("aid")] = data
		s.event(1103, a.ID, &c.c.ID, nil)
	}
}

func (s *Server) attachmentMeta(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.ciphers[r.PathValue("id")]
	if c == nil {
		fail(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	if _, ok := s.view(c, a.ID); !ok {
		fail(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	// Absolute and on a foreign host, as a server behind a public name
	// answers; the client must rewrite it onto its own base URL.
	writeJSON(w, map[string]any{"url": "https://public.invalid/attachments/" + c.c.ID + "/" + r.PathValue("aid") + "?token=t"})
}

func (s *Server) attachmentFile(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.ciphers[r.PathValue("id")]
	if c == nil || r.URL.Query().Get("token") != "t" {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	data, ok := c.files[r.PathValue("aid")]
	if !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) attachmentDelete(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.editable(w, r.PathValue("id"), a)
	if c == nil {
		return
	}
	aid := r.PathValue("aid")
	c.c.Attachments = slices.DeleteFunc(c.c.Attachments, func(x bitwarden.Attachment) bool { return x.ID == aid })
	delete(c.files, aid)
}

func (s *Server) createSend(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.Send
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	body.ID, body.AccessID = newID(), newID()
	s.sends[body.ID] = body
	s.sendOwner[body.ID] = a.ID
	writeJSON(w, body)
}

func (s *Server) deleteSend(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := r.PathValue("id")
	if s.sendOwner[id] != a.ID {
		fail(w, http.StatusNotFound, "Send not found")
		return
	}
	delete(s.sends, id)
	delete(s.sendOwner, id)
}

// admin checks that the account manages the organization of the request.
func (s *Server) admin(w http.ResponseWriter, r *http.Request, a *Account) *organization {
	org := s.orgs[r.PathValue("org")]
	if org == nil || !manages(s.membership(org.id, a.ID)) {
		fail(w, http.StatusUnauthorized, "You don't have permission")
		return nil
	}
	return org
}

func (s *Server) orgCollections(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	var out []bitwarden.CollectionDetails
	for _, col := range s.collections {
		if col.orgID != org.id {
			continue
		}
		d := bitwarden.CollectionDetails{Collection: bitwarden.Collection{ID: col.id, OrganizationID: org.id, Name: col.name}, Users: []bitwarden.CollectionAccess{}}
		for _, m := range org.members {
			for _, acc := range m.collections {
				if acc.ID == col.id {
					d.Users = append(d.Users, bitwarden.CollectionAccess{ID: m.id, ReadOnly: acc.ReadOnly, HidePasswords: acc.HidePasswords, Manage: acc.Manage})
				}
			}
		}
		out = append(out, d)
	}
	writeJSON(w, map[string]any{"data": out})
}

func (s *Server) applyUsers(org *organization, colID string, users []bitwarden.CollectionAccess) {
	for _, m := range org.members {
		m.collections = slices.DeleteFunc(m.collections, func(x bitwarden.CollectionAccess) bool { return x.ID == colID })
		for _, u := range users {
			if u.ID == m.id {
				m.collections = append(m.collections, bitwarden.CollectionAccess{ID: colID, ReadOnly: u.ReadOnly, HidePasswords: u.HidePasswords, Manage: u.Manage})
			}
		}
	}
}

func (s *Server) createCollection(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.CollectionRequest
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	col := &collection{id: newID(), orgID: org.id, name: body.Name}
	s.collections[col.id] = col
	s.applyUsers(org, col.id, body.Users)
	s.event(1300, a.ID, nil, &col.id)
	writeJSON(w, bitwarden.Collection{ID: col.id, OrganizationID: org.id, Name: col.name})
}

func (s *Server) updateCollection(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.CollectionRequest
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	col := s.collections[r.PathValue("id")]
	if col == nil || col.orgID != org.id {
		fail(w, http.StatusNotFound, "Collection not found")
		return
	}
	col.name = body.Name
	s.applyUsers(org, col.id, body.Users)
	writeJSON(w, bitwarden.Collection{ID: col.id, OrganizationID: org.id, Name: col.name})
}

func (s *Server) deleteCollection(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	id := r.PathValue("id")
	delete(s.collections, id)
	s.applyUsers(org, id, nil)
}

func (s *Server) members(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	var out []bitwarden.Member
	for _, m := range org.members {
		role := m.role
		// Vaultwarden reports managers as the custom type.
		if role == bitwarden.MemberManager {
			role = bitwarden.MemberCustom
		}
		out = append(out, bitwarden.Member{ID: m.id, UserID: m.userID, Email: m.email, Status: m.status, Type: role, AccessAll: m.accessAll, Collections: slices.Clone(m.collections)})
	}
	writeJSON(w, map[string]any{"data": out})
}

func (s *Server) invite(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.MemberRequest
	if err := decode(r, &body); err != nil || body.Groups == nil || body.Permissions == nil {
		// Vaultwarden rejects a body without groups and permissions.
		fail(w, http.StatusUnprocessableEntity, "missing field `groups`")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	for _, email := range body.Emails {
		m := &member{id: newID(), email: email, status: bitwarden.MemberInvited, role: body.Type, collections: body.Collections}
		for _, acct := range s.accounts {
			// Without mail, Vaultwarden accepts invitations of existing
			// accounts on their behalf.
			if strings.EqualFold(acct.Email, email) {
				m.userID, m.status = acct.ID, bitwarden.MemberAccepted
			}
		}
		org.members = append(org.members, m)
	}
}

func (s *Server) findMember(w http.ResponseWriter, org *organization, id string) *member {
	for _, m := range org.members {
		if m.id == id {
			return m
		}
	}
	fail(w, http.StatusNotFound, "User not found")
	return nil
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request, a *Account) {
	var body bitwarden.MemberRequest
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	if m := s.findMember(w, org, r.PathValue("id")); m != nil {
		role := body.Type
		// ...and accepts the custom type back as manager. Access to every
		// collection follows from the type and the permissions alone; the
		// accessAll of the body is ignored, as Vaultwarden does.
		m.accessAll = role == bitwarden.MemberCustom && body.Permissions["editAnyCollection"] &&
			body.Permissions["deleteAnyCollection"] && body.Permissions["createNewCollections"]
		if role == bitwarden.MemberCustom {
			role = bitwarden.MemberManager
		}
		m.role, m.collections = role, body.Collections
	}
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request, a *Account) {
	var body struct {
		Key string `json:"key"`
	}
	if err := decode(r, &body); err != nil || body.Key == "" {
		fail(w, http.StatusBadRequest, "key required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	m := s.findMember(w, org, r.PathValue("id"))
	if m == nil {
		return
	}
	if m.status != bitwarden.MemberAccepted {
		fail(w, http.StatusBadRequest, "User in invalid state")
		return
	}
	m.key, m.status = body.Key, bitwarden.MemberConfirmed
}

func (s *Server) memberStatus(status bitwarden.MemberStatus) func(http.ResponseWriter, *http.Request, *Account) {
	return func(w http.ResponseWriter, r *http.Request, a *Account) {
		s.mu.Lock()
		defer s.mu.Unlock()
		org := s.admin(w, r, a)
		if org == nil {
			return
		}
		if m := s.findMember(w, org, r.PathValue("id")); m != nil {
			m.status = status
		}
	}
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	org := s.admin(w, r, a)
	if org == nil {
		return
	}
	id := r.PathValue("id")
	org.members = slices.DeleteFunc(org.members, func(m *member) bool { return m.id == id })
}

func (s *Server) publicKey(w http.ResponseWriter, r *http.Request, _ *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct := s.accounts[r.PathValue("id")]
	if acct == nil {
		fail(w, http.StatusNotFound, "User doesn't exist")
		return
	}
	writeJSON(w, map[string]string{"userId": acct.ID, "publicKey": acct.publicKey})
}

func (s *Server) orgEvents(w http.ResponseWriter, r *http.Request, a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.admin(w, r, a) == nil {
		return
	}
	out := slices.Clone(s.events)
	slices.Reverse(out)
	writeJSON(w, map[string]any{"data": out, "continuationToken": nil})
}
