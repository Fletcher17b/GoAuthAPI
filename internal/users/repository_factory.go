package users

import "database/sql"

func NewUserRepo(driver string, db *sql.DB) Repository {
	switch driver {
	case "sqlite":
		sqlite_repo := NewSQLiteRepository(db)

		if sqlite_repo == nil {
			panic("Unable to Spin up Refresh token Repository")
		}
		return sqlite_repo
	case "postgres":
		psql_repo := NewPostgresRepository(db)
		if psql_repo == nil {
			panic("Unable to Spin up Refresh token Repository")
		}

		return psql_repo
	default:
		panic("unsupported database driver")
	}
}
