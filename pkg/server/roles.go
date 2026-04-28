package server

type Permission string

const (
    PermissionRead   Permission = "READ"
    PermissionWrite  Permission = "WRITE"
    PermissionDelete Permission = "DELETE"
)

type FileMetadata struct {
    Owner  string
    ACL    map[string][]Permission
    Public bool
}

type UserData struct {
    Roles []string
}