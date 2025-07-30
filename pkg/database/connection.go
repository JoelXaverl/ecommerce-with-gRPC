package database

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq" // tanda underscrode itu maksudnya bahwa ini import yang nameless, saya tdk pake "pq" nya melainkan hanya ignin site effect atau hanya ingin apa yg dijalanakn oleh library tsb
)

func ConnectDB(ctx context.Context, connStr string) *sql.DB {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	err = db. PingContext(ctx)
	if err != nil {
		panic(err)
	}
	
	return db
}