package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"electronic-voting/util/ctxkey"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/exp/slices"
)

var pool *pgxpool.Pool

var migrationsRun = false

type migrationFile struct {
	filename  string
	sha256sum []byte
}

func InitDB(ctx context.Context, wg *sync.WaitGroup, db_username, db_password, db_host, db_port, db_name string) (err error) {
	config, err := poolConfig(db_username, db_password, db_host, db_port, db_name)
	if err != nil {
		return
	}

	pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return
	}

	// automatically close connection pool when context is canceled
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		CloseDB()
	}()

	return
}

// poolConfig returns the config for connecting to the database. The user, password and database are
// set on the config directly, so they're used exactly as given, whatever characters they contain
// (like the / a generated password often has). The host and port still go through ParseConfig,
// since it sets up TLS and fallback hosts for the host it parses, and setting the host afterward
// would leave those set up for its default host.
func poolConfig(db_username, db_password, db_host, db_port, db_name string) (config *pgxpool.Config, err error) {
	config, err = pgxpool.ParseConfig("host=" + quoteConnValue(db_host) + " port=" + quoteConnValue(db_port))
	if err != nil {
		return
	}

	config.ConnConfig.User = db_username
	config.ConnConfig.Password = db_password
	config.ConnConfig.Database = db_name

	return
}

// quoteConnValue quotes a value for a keyword/value connection string, escaping backslashes and
// single quotes
func quoteConnValue(value string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value) + "'"
}

func RunMigrations(ctx context.Context) (err error) {
	if migrationsRun {
		return
	}

	tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
	// get a better method for finding this (may be able to use runtime.Caller())
	migration_dir := "../migrations"

	entries, err := os.ReadDir(migration_dir)
	if err != nil {
		err = fmt.Errorf("error reading migration directory (%s): %w", migration_dir, err)
		return
	}
	slices.SortFunc(entries, func(entry_a, entry_b fs.DirEntry) int {
		file_info_a, _ := entry_a.Info()
		file_info_b, _ := entry_b.Info()

		number_a, _ := strconv.Atoi(strings.Split(file_info_a.Name(), "_")[0])
		number_b, _ := strconv.Atoi(strings.Split(file_info_b.Name(), "_")[0])
		return number_a - number_b
	})

	log.Print("running migrations")

	_, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS sql_migrations(file_name TEXT PRIMARY KEY, sha256 BYTEA);")
	if err != nil {
		log.Print("error creating migrations table")
		return
	}

	rows, err := tx.Query(ctx, "SELECT file_name, sha256 FROM sql_migrations;")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Print("error querying migrations")
		return
	}

	defer rows.Close()

	// build list of applied files
	applied_migrations := []migrationFile{}
	for rows.Next() {
		var applied_migration migrationFile
		err = rows.Scan(&applied_migration.filename, &applied_migration.sha256sum)
		if err != nil {
			log.Print("error encountered while reading migrations from database")
			return
		}
		applied_migrations = append(applied_migrations, applied_migration)
	}

	rows.Close()
	if err = rows.Err(); err != nil {
		log.Print("error closing rows for query on existing migrations")
		return
	}

	for _, entry := range entries {
		file_info, _ := entry.Info()

		var file_bytes []byte
		file_bytes, err = os.ReadFile(path.Join(migration_dir, file_info.Name()))
		if err != nil {
			log.Print("error reading migration file")
			return err
		}

		file_hash := sha256.Sum256(file_bytes)

		// see if already applied
		if migration_index := slices.IndexFunc(applied_migrations, func(applied_migration migrationFile) bool {
			return applied_migration.filename == file_info.Name()
		}); migration_index != -1 {
			// if applied, make sure not changed
			if !bytes.Equal(file_hash[:], applied_migrations[migration_index].sha256sum) {
				err = fmt.Errorf("migration file '%s' was modified after being previously applied", file_info.Name())
				log.Print("error checking applied migrations")
				return
			} else {
				// if already applied, go to next
				continue
			}
		}

		log.Printf("applying migration: %s", file_info.Name())
		// apply migration
		_, err = tx.Exec(ctx, string(file_bytes))
		if err != nil {
			log.Printf("error applying migration: %s", file_info.Name())
			return
		}

		// record migration
		_, err = tx.Exec(ctx,
			"INSERT INTO sql_migrations(file_name, sha256) VALUES( $1, $2 );",
			file_info.Name(),
			file_hash[:])
		if err != nil {
			log.Printf("error recording migration: %s", file_info.Name())
			return
		}
	}

	migrationsRun = true

	return
}

func CloseDB() {
	pool.Close()
}

// BeginTx begins a transaction in the database. tx is not automatically
// rolled back when the passed-in context is canceled, and must be
// rolled back by the caller where appropriate
func BeginTx(ctx context.Context) (tx pgx.Tx, err error) {
	txOptions := pgx.TxOptions{}

	tx, err = pool.BeginTx(ctx, txOptions)

	return
}

func ErrorIsDuplicateKeyValue(err error) bool {
	// use errors.As so wrapped errors are still detected
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
