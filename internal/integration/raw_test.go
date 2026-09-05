package integration

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// openRaw abre la base saltándose internal/store, para simular a quien tiene el
// fichero y un cliente de SQLite.
func openRaw(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path)
}
