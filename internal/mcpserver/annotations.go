package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

// toolClass is how a tool touches the vault and the world, which clients use
// to decide what may run without asking a human.
type toolClass int

const (
	// classRead only reads the vault.
	classRead toolClass = iota
	// classExport reads the vault and hands a value out of the process.
	classExport
	// classWrite changes the vault without losing anything: history, trash
	// or an explicit undo keep what was there.
	classWrite
	// classDestructive changes or removes something that is not kept.
	classDestructive
)

// toolClasses lists every tool. A tool missing here is a programming error
// that the tests catch before release.
var toolClasses = map[string]toolClass{
	"get_status": classRead, "list_collections": classRead, "list_items": classRead,
	"search_items": classRead, "get_item": classRead, "find_by_value": classRead,
	"find_copies": classRead, "check_items": classRead, "list_members": classRead,
	"list_events": classRead,

	"get_secret": classExport, "get_attachment": classExport, "issue_value_link": classExport,
	"share_with_human": classExport,

	"create_item": classWrite, "restore_item": classWrite, "add_attachment": classWrite,
	"request_value_upload": classWrite, "invite_member": classWrite, "confirm_member": classWrite,
	"create_collection": classWrite,

	"update_item": classDestructive, "delete_item": classDestructive, "delete_attachment": classDestructive,
	"revoke_share": classDestructive, "set_item_collections": classDestructive,
	"update_member": classDestructive, "change_member": classDestructive,
	"update_collection": classDestructive, "delete_collection": classDestructive,
}

func annotationsFor(name string) *mcp.ToolAnnotations {
	yes, no := true, false
	switch toolClasses[name] {
	case classRead:
		return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &no}
	case classExport:
		// Nothing in the vault changes, but a value leaves for whoever holds
		// the result.
		return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &yes}
	case classWrite:
		return &mcp.ToolAnnotations{DestructiveHint: &no, OpenWorldHint: &no}
	case classDestructive:
		return &mcp.ToolAnnotations{DestructiveHint: &yes, OpenWorldHint: &no}
	default:
		return &mcp.ToolAnnotations{DestructiveHint: &yes, OpenWorldHint: &yes}
	}
}
