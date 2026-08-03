package refresh

import "database/sql"

func NewRefreshRepo(driver string, db *sql.DB) RefreshTokenRepository {
	switch driver {
	case "sqlite":
		sqlite_repo := NewSqliteRefreshRepo(db)

		if sqlite_repo == nil {
			panic("Unable to Spin up Refresh token Repository")
		}
		return sqlite_repo
	case "postgres":
		psql_repo := NewPostgresRefreshRepo(db)
		if psql_repo == nil {
			panic("Unable to Spin up Refresh token Repository")
		}

		return psql_repo
	default:
		panic("unsupported database driver")
	}
}
