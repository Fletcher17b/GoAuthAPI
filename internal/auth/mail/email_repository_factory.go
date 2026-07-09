package mail

import "database/sql"

func NewEmailVerificationRepo(driver string, db *sql.DB) EmailVerificationRepository {
	switch driver {
	case "sqlite":
		sqlite_repo := NewEmailVerificationSQLiteRepo(db)

		if sqlite_repo == nil {
			panic("Unable to Spin up EmailVerification Repository")
		}
		return sqlite_repo
	case "postgres":
		psql_repo := NewEmailVerificationPostgresRepo(db)
		if psql_repo == nil {
			panic("Unable to Spin up EmailVerification Repository")
		}

		return psql_repo
	default:
		panic("unsupported database driver")
	}
}
