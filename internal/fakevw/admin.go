package fakevw

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/bitwarden"
)

// AddMember puts an account into an organization with a role, confirmed.
func (s *Server) AddMember(orgID string, a *Account, role bitwarden.MemberType) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orgs[orgID]
	o.members = append(o.members, &member{id: newID(), userID: a.ID, email: a.Email, status: bitwarden.MemberConfirmed, role: role})
}

// panel is the fake admin panel: the accounts it created by invitation, the
// accounts it disabled, and the sessions it issued.
type panel struct {
	token    string
	sessions map[string]bool
	invited  map[string]string // id -> email
	disabled map[string]bool
	logins   int
}

// EnableAdmin turns the admin panel on with a token, as ADMIN_TOKEN does.
func (s *Server) EnableAdmin(token string) {
	s.mu.Lock()
	s.panel = &panel{token: token, sessions: map[string]bool{}, invited: map[string]string{}, disabled: map[string]bool{}}
	s.mu.Unlock()
}

// ExpireAdminSessions drops every panel session, as their lifetime running out
// does.
func (s *Server) ExpireAdminSessions() {
	s.mu.Lock()
	s.panel.sessions = map[string]bool{}
	s.mu.Unlock()
}

// AdminLogins counts successful panel logins.
func (s *Server) AdminLogins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.panel.logins
}

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin", s.adminLogin)
	mux.HandleFunc("GET /admin/users", s.panelAuthed(s.adminUsers))
	mux.HandleFunc("GET /admin/users/by-mail/{email}", s.panelAuthed(s.adminUserByMail))
	mux.HandleFunc("GET /admin/users/{id}", s.panelAuthed(s.adminUser))
	mux.HandleFunc("POST /admin/invite", s.panelAuthed(s.panelJSON(s.adminInvite)))
	mux.HandleFunc("POST /admin/users/{id}/invite/resend", s.panelAuthed(s.panelJSON(s.adminAction("resend"))))
	mux.HandleFunc("POST /admin/users/{id}/{action}", s.panelAuthed(s.panelJSON(s.adminAction(""))))
	mux.HandleFunc("POST /admin/organizations/{id}/delete", s.panelAuthed(s.panelJSON(s.adminDeleteOrg)))
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"version": "2025.12.0", "server": map[string]string{"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}})
	})
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.panel == nil || r.ParseForm() != nil || r.PostForm.Get("token") != s.panel.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	session := newID()
	s.panel.sessions[session] = true
	s.panel.logins++
	http.SetCookie(w, &http.Cookie{Name: "VW_ADMIN", Value: session, Path: "/admin", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html>admin</html>"))
}

// panelAuthed checks the session cookie; the caller's handler runs with mu held.
func (s *Server) panelAuthed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		ck, err := r.Cookie("VW_ADMIN")
		if s.panel == nil || err != nil || !s.panel.sessions[ck.Value] {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// panelJSON answers 404 to a POST without a JSON content type, as the panel's
// router does.
func (s *Server) panelJSON(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		h(w, r)
	}
}

func (s *Server) userJSON(id string) map[string]any {
	enabled := !s.panel.disabled[id]
	if email, ok := s.panel.invited[id]; ok {
		return map[string]any{
			"id": id, "email": email, "name": email, "_status": 1, "userEnabled": enabled,
			"twoFactorEnabled": false, "createdAt": time.Now().UTC().Format("2006-01-02 15:04:05 +00:00"),
			"lastActive": nil, "organizations": []any{},
		}
	}
	a := s.accounts[id]
	status := 0
	if !enabled {
		status = 2
	}
	orgs := []any{}
	for _, o := range s.orgs {
		for _, m := range o.members {
			if m.userID == id {
				orgs = append(orgs, map[string]any{"id": o.id, "name": o.name, "type": m.role, "status": m.status})
			}
		}
	}
	last := time.Now().UTC().Format("2006-01-02 15:04:05 +00:00")
	return map[string]any{
		"id": a.ID, "email": a.Email, "name": a.Email, "_status": status, "userEnabled": enabled,
		"twoFactorEnabled": false, "createdAt": last, "lastActive": last, "organizations": orgs,
	}
}

func (s *Server) userIDs() []string {
	var ids []string
	for id := range s.accounts {
		ids = append(ids, id)
	}
	for id := range s.panel.invited {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (s *Server) adminUsers(w http.ResponseWriter, _ *http.Request) {
	out := []any{}
	for _, id := range s.userIDs() {
		out = append(out, s.userJSON(id))
	}
	writeJSON(w, out)
}

func (s *Server) adminUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.accounts[id]; !ok {
		if _, ok := s.panel.invited[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	writeJSON(w, s.userJSON(id))
}

func (s *Server) adminUserByMail(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	for _, id := range s.userIDs() {
		if strings.EqualFold(s.userJSON(id)["email"].(string), email) {
			writeJSON(w, s.userJSON(id))
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) adminInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Email == "" {
		fail(w, http.StatusBadRequest, "email is required")
		return
	}
	for _, id := range s.userIDs() {
		if strings.EqualFold(s.userJSON(id)["email"].(string), in.Email) {
			fail(w, http.StatusBadRequest, "User already exists")
			return
		}
	}
	id := newID()
	s.panel.invited[id] = in.Email
	writeJSON(w, s.userJSON(id))
}

func (s *Server) adminAction(fixed string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_, account := s.accounts[id]
		_, invited := s.panel.invited[id]
		if !account && !invited {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		action := fixed
		if action == "" {
			action = r.PathValue("action")
		}
		switch action {
		case "disable":
			s.panel.disabled[id] = true
		case "enable":
			delete(s.panel.disabled, id)
		case "deauth", "resend":
		case "delete":
			delete(s.accounts, id)
			delete(s.panel.invited, id)
			for _, o := range s.orgs {
				o.members = slices.DeleteFunc(o.members, func(m *member) bool { return m.userID == id })
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (s *Server) adminDeleteOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.orgs[id]; !ok {
		fail(w, http.StatusBadRequest, "Organization doesn't exist")
		return
	}
	delete(s.orgs, id)
	for cid, c := range s.collections {
		if c.orgID == id {
			delete(s.collections, cid)
		}
	}
}
