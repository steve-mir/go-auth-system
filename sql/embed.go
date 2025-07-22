package sql

import "embed"

//go:embed migrations/*.sql
var Files embed.FS
