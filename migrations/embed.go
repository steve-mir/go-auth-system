package migrations

import "embed"

//go:embed ../sql/migrations/*.sql
var Files embed.FS
