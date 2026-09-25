package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/links"
	"github.com/Alexander-Zhukov/vaultwarden-agentic-mcp/internal/vault"
)

// LinkHandlers serves the one-time link endpoints. They carry no bearer token:
// the unguessable path is the credential, and it works once.
func LinkHandlers(deps Deps) http.Handler {
	s := &server{Deps: deps}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/links/{token}", s.serveDownload)
	mux.HandleFunc("GET /v1/upload/{token}", s.serveUploadForm)
	mux.HandleFunc("POST /v1/upload/{token}", s.serveUpload)
	mux.HandleFunc("PUT /v1/upload/{token}", s.serveUpload)
	return secureHeaders(onlyFrom(deps.Config.Links.Sources, noHead(mux)))
}

// noHead refuses HEAD, which the GET routes would otherwise answer: a link
// preview or a scanner probing with HEAD would spend a one-time link.
func noHead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// onlyFrom limits link redemption to the configured source ranges, so a link
// that leaked out of the network it was meant for is useless.
func onlyFrom(sources []netip.Prefix, next http.Handler) http.Handler {
	if len(sources) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, err := netip.ParseAddrPort(r.RemoteAddr)
		if err == nil && slices.ContainsFunc(sources, func(p netip.Prefix) bool { return p.Contains(addr.Addr().Unmap()) }) {
			next.ServeHTTP(w, r)
			return
		}
		linkGone(w)
	})
}

// inScope checks, at redemption, that the item is still within the issuing
// client's collections: it may have moved since the link was issued.
func inScope(snap *vault.Snapshot, it *vault.Item, collections []string) bool {
	if len(collections) == 0 {
		return true
	}
	for _, id := range it.CollectionIDs {
		name := snap.CollectionName(id)
		if slices.ContainsFunc(collections, func(c string) bool { return c == id || c == name }) {
			return true
		}
	}
	return false
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// linkGone answers every unusable token the same way, so a probe cannot tell
// an expired link from one that never existed.
func linkGone(w http.ResponseWriter) {
	http.Error(w, "this link does not exist, has expired or was already used", http.StatusGone)
}

// audit records what happened to a link. The token is never part of it.
func (s *server) audit(ctx context.Context, level slog.Level, event string, l links.Link, err error) {
	attrs := []slog.Attr{
		slog.String("event", event), slog.String("kind", string(l.Kind)), slog.String("client", l.Client),
		slog.String("item_id", l.ItemID), slog.String("field", l.Field), slog.String("attachment", l.Attachment),
	}
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
	}
	s.Logger.LogAttrs(ctx, level, "one-time link", attrs...)
}

func (s *server) serveDownload(w http.ResponseWriter, r *http.Request) {
	l, ok := s.Links.Take(r.PathValue("token"), links.KindValue, links.KindAttachment)
	if !ok {
		s.Metrics.Links.WithLabelValues(string(links.KindValue), "rejected").Inc()
		linkGone(w)
		return
	}
	ctx := r.Context()
	snap, err := s.Vault.Snapshot(ctx)
	if err != nil {
		s.fail(ctx, w, l, err)
		return
	}
	it, err := snap.Item(vault.ItemRef{Ref: l.ItemID})
	if err == nil && (it.Deleted != nil || !inScope(snap, it, l.Collections)) {
		err = fmt.Errorf("%w: the item left the issuing client's reach", vault.ErrNotFound)
	}
	if err != nil {
		s.fail(ctx, w, l, err)
		return
	}
	switch l.Kind {
	case links.KindAttachment:
		if !it.Viewable || it.Reprompt != 0 {
			s.fail(ctx, w, l, fmt.Errorf("%w: the item's secrets are hidden from this account or need re-prompt", vault.ErrReadOnly))
			return
		}
		att, data, err := s.Vault.AttachmentContent(ctx, vault.ItemRef{Ref: it.ID}, l.Attachment)
		if err != nil {
			s.fail(ctx, w, l, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": att.FileName}))
		s.redeemed(ctx, w, l, data)
	case links.KindValue:
		value, _, err := valueOf(it, l.Field, s.Clock())
		if err != nil {
			s.fail(ctx, w, l, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		s.redeemed(ctx, w, l, []byte(value))
	case links.KindUpload:
		linkGone(w)
	}
}

func (s *server) redeemed(ctx context.Context, w http.ResponseWriter, l links.Link, data []byte) {
	s.Metrics.Links.WithLabelValues(string(l.Kind), "redeemed").Inc()
	s.audit(ctx, slog.LevelInfo, "redeemed", l, nil)
	// A client that vanished mid-response has nothing to retry with anyway:
	// the link is spent.
	_, _ = w.Write(data)
}

func (s *server) fail(ctx context.Context, w http.ResponseWriter, l links.Link, err error) {
	s.Metrics.Links.WithLabelValues(string(l.Kind), "rejected").Inc()
	s.audit(ctx, slog.LevelWarn, "failed", l, err)
	status := http.StatusBadGateway
	if errors.Is(err, vault.ErrNotFound) {
		status = http.StatusGone
	}
	http.Error(w, "the value is no longer available", status)
}

var uploadForm = template.Must(template.New("upload").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Store a secret</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#1d1d1f;background:#fff}
textarea,input[type=file]{width:100%;box-sizing:border-box;margin:.5rem 0 1rem}
textarea{min-height:8rem;font-family:ui-monospace,monospace}
button{font:inherit;padding:.5rem 1.25rem}
.meta{color:#6e6e73}
@media (prefers-color-scheme:dark){body{color:#f5f5f7;background:#1d1d1f}.meta{color:#a1a1a6}}
</style></head><body>
<h1>Store a secret</h1>
<p class="meta">Item <strong>{{.Item}}</strong>, {{if .File}}attachment <strong>{{.File}}</strong>{{else}}field <strong>{{.Field}}</strong>{{end}}.
The value goes straight into the vault. This page works once and expires {{.Expires}}.</p>
<form method="post" enctype="multipart/form-data">
{{if .File}}<input type="file" name="file" required>{{else}}<textarea name="value" required autocomplete="off" spellcheck="false"></textarea>{{end}}
<button type="submit">Store</button>
</form></body></html>`))

func (s *server) serveUploadForm(w http.ResponseWriter, r *http.Request) {
	l, ok := s.Links.Peek(r.PathValue("token"), links.KindUpload)
	if !ok {
		linkGone(w)
		return
	}
	name := l.ItemID
	if snap, err := s.Vault.Snapshot(r.Context()); err == nil {
		if it, err := snap.Item(vault.ItemRef{Ref: l.ItemID}); err == nil {
			name = it.Name
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := uploadForm.Execute(w, map[string]string{
		"Item": name, "Field": l.Field, "File": l.Attachment, "Expires": formatTime(l.Expires, s.Config.Location),
	})
	if err != nil {
		s.Logger.Warn("render upload form", slog.Any("error", err))
	}
}

func (s *server) serveUpload(w http.ResponseWriter, r *http.Request) {
	l, ok := s.Links.Take(r.PathValue("token"), links.KindUpload)
	if !ok {
		s.Metrics.Links.WithLabelValues(string(links.KindUpload), "rejected").Inc()
		linkGone(w)
		return
	}
	ctx := r.Context()
	limit := s.Config.Tuning.MaxUploadValue
	if l.Attachment != "" {
		limit = s.Config.MaxAttachment
	}
	data, err := readUpload(w, r, limit, l.Attachment != "")
	if err != nil {
		s.fail(ctx, w, l, fmt.Errorf("%w: %w", vault.ErrInvalid, err))
		return
	}
	ref := vault.ItemRef{Ref: l.ItemID}
	snap, err := s.Vault.Snapshot(ctx)
	if err != nil {
		s.fail(ctx, w, l, err)
		return
	}
	it, err := snap.Item(ref)
	if err == nil && (it.Deleted != nil || !inScope(snap, it, l.Collections)) {
		err = fmt.Errorf("%w: the item left the issuing client's reach", vault.ErrNotFound)
	}
	if err != nil {
		s.fail(ctx, w, l, err)
		return
	}
	if l.Attachment != "" {
		_, err = s.Vault.AddAttachment(ctx, ref, l.Attachment, data)
	} else {
		value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if value == "" {
			s.fail(ctx, w, l, fmt.Errorf("%w: empty value", vault.ErrInvalid))
			return
		}
		_, err = s.Vault.Update(ctx, ref, func(it *vault.Item) error { return storeField(it, l.Field, value) })
	}
	if err != nil {
		s.fail(ctx, w, l, err)
		return
	}
	s.Metrics.Links.WithLabelValues(string(links.KindUpload), "redeemed").Inc()
	s.Metrics.Mutations.WithLabelValues("upload").Inc()
	s.audit(ctx, slog.LevelInfo, "uploaded", l, nil)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "stored\n")
}

// readUpload reads the uploaded value. A PUT body is always the raw value,
// whatever its Content-Type: curl --data-binary labels a raw body as a
// urlencoded form. A POST is the browser form — urlencoded with "value", or
// multipart with "value" or "file" — or raw when it carries no form type.
func readUpload(w http.ResponseWriter, r *http.Request, limit int64, file bool) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit+64<<10)
	if r.Method == http.MethodPut {
		return readLimited(r.Body, limit)
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")) // an unparsable type is a raw body
	switch ct {
	case "multipart/form-data":
		mr, err := r.MultipartReader()
		if err != nil {
			return nil, fmt.Errorf("read form: %w", err)
		}
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				return nil, errors.New("the form has no value")
			}
			if err != nil {
				return nil, fmt.Errorf("read form: %w", err)
			}
			if part.FormName() == "value" || part.FormName() == "file" {
				return readLimited(part, limit)
			}
		}
	case "application/x-www-form-urlencoded":
		if file {
			return nil, errors.New("a file upload needs a multipart form or a raw body")
		}
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("read form: %w", err)
		}
		return []byte(r.PostForm.Get("value")), nil
	default:
		return readLimited(r.Body, limit)
	}
}

func readLimited(rd io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(rd, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("the upload exceeds %d bytes", limit)
	}
	return data, nil
}

func storeField(it *vault.Item, field, value string) error {
	switch {
	case field == "password":
		it.Password = value
	case field == "totp":
		it.TOTP = value
	case field == "notes":
		it.Notes = value
	case field == "ssh_private_key":
		if it.SSH == nil {
			it.SSH = &vault.SSHKey{}
		}
		it.SSH.Private = value
	case strings.HasPrefix(field, "field:"):
		name := strings.TrimPrefix(field, "field:")
		for i := range it.Fields {
			if it.Fields[i].Name == name {
				// An uploaded value is a secret whatever the field was
				// before: a text field would show it in get_item.
				it.Fields[i].Value, it.Fields[i].Kind = value, vault.FieldHidden
				return nil
			}
		}
		it.Fields = append(it.Fields, vault.Field{Name: name, Value: value, Kind: vault.FieldHidden})
	default:
		return fmt.Errorf("%w: cannot store into %q", vault.ErrInvalid, field)
	}
	return nil
}
