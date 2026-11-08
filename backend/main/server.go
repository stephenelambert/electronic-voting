package main

import (
	"context"
	"electronic-voting/database"
	"electronic-voting/localopaque"
	"electronic-voting/localsigner"
	"electronic-voting/route"
	"electronic-voting/util/account"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/dbcrypt"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

// db_username is the username to use for the database
var db_username string

// db_password is the password to use for the database
var db_password string

// db_host is the host of the database
var db_host string

// db_port is the port of the database
var db_port string

// db_name is the name of the database
var db_name string

// api_host is the host to listen on for the API
var api_host string

// the username for a user to make as an admin
var admin_username string

// admin_setup_token is the token that claims the admin account when it's registered, if the account
// hasn't registered yet
var admin_setup_token string

var wg = &sync.WaitGroup{}

func main() {
	parseArgs()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// set up the database key first, since the startup tasks read and write encrypted columns
	err := dbcrypt.Init()
	if err != nil {
		log.Printf("error setting up database encryption: %v", err)
		return
	}

	// set up DB connection
	err = database.InitDB(ctx, wg, db_username, db_password, db_host, db_port, db_name)
	if err != nil {
		log.Printf("error initializing database: %v", err)
		return
	}

	err = runStartup(ctx)
	// if there's an issue during startup, log and initiate the shutdown process
	if err != nil {
		log.Printf("shutting down after error running startup tasks: %v", err)
		shutdown(cancel, func(ctx context.Context) error { return nil })
		return
	}

	// set up server
	srv := &http.Server{
		Addr:         api_host,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      route.Router(),
	}

	wg.Add(1)
	// run server in goroutine
	go func() {
		defer wg.Done()
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	// reconfigure interrupt signal to shut down the server
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// block here until interrupt signal
	<-c

	// initiate shutdown sequence
	shutdown(cancel, srv.Shutdown)
}

func getEnvWithDefault(var_name, default_val string) string {
	val, ok := os.LookupEnv(var_name)
	if ok {
		return val
	}
	return default_val
}

// parseArgs parses the command-line arguments and environment variables
func parseArgs() {
	flag.StringVar(&db_username, "db_user", getEnvWithDefault("DB_USER", "postgres"), "username for the database")
	flag.StringVar(&db_password, "db_pass", getEnvWithDefault("DB_PASS", "password"), "password for the database user")
	flag.StringVar(&db_host, "db_host", getEnvWithDefault("DB_HOST", "localhost"), "host for the database")
	flag.StringVar(&db_port, "db_port", getEnvWithDefault("DB_PORT", "5432"), "the port to access the database")
	flag.StringVar(&db_name, "db_name", getEnvWithDefault("DB_NAME", "postgres"), "the name of the database")
	flag.StringVar(&api_host, "api_host", getEnvWithDefault("API_HOST", ":5172"), "hostname/IP and port to listen on")
	flag.StringVar(&admin_username, "admin_user", getEnvWithDefault("ADMIN_USER", ""), "username of the global admin account to create")
	flag.StringVar(&admin_setup_token, "admin_setup_token", getEnvWithDefault("ADMIN_SETUP_TOKEN", ""), "token for claiming the admin account when creating it")
	flag.Parse()
}

// runStartup runs all of the startup tasks. All tasks that could update
// the database are done in a single database transaction to avoid ruining
// a clean state.
func runStartup(parentCtx context.Context) (err error) {
	// run startup tasks with dedicated
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	tx, err := database.BeginTx(ctx)
	if err != nil {
		log.Printf("error beginning transaction for startup tasks: %v", err)
		return
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// add transaction to the context for easy use within startup functions
	ctx = context.WithValue(ctx, ctxkey.Key("transaction"), tx)

	// run migrations immediately after database connection is established
	if err = database.RunMigrations(ctx); err != nil {
		log.Printf("error running migrations: %v", err)
		return
	}

	if err = localsigner.Init(ctx); err != nil {
		log.Printf("error setting up local signer: %v", err)
		return
	}

	if err = localopaque.Init(ctx); err != nil {
		log.Printf("error setting up OPAQUE: %v", err)
		return
	}

	// add the admin
	if err = account.AddAdmin(ctx, admin_username, admin_setup_token); err != nil {
		log.Printf("failed to create/update admin user: %v", err)
		return
	}
	admin_setup_token = ""

	if err = tx.Commit(ctx); err != nil { // commit the transaction
		log.Printf("error committing transaction for startup tasks: %v", err)
		return
	}

	return
}

// shutdown initiates the shutdown sequence by cancelling the main context
// and shutting down the HTTP server.
// If things take too long to shut down gracefully (5 seconds), the program exits.
func shutdown(ctxCancel context.CancelFunc, shutdownFunc func(context.Context) error) {
	log.Println("shutting down")

	// give time to finish requests in progress before killing server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer shutdownCancel()

	// cancel the main context so everything should start closing
	ctxCancel()

	// call the shutdown function if one is passed in
	if shutdownFunc != nil {
		if err := shutdownFunc(shutdownCtx); err != nil {
			log.Printf("error shutting down server: %s", err.Error())
		}
	}

	wgFinished := make(chan bool)
	go func() {
		wg.Wait()
		wgFinished <- true
	}()

	select {
	case <-wgFinished:
		log.Print("all shutdown procedures finished")
	case <-shutdownCtx.Done():
		log.Print("shutdown timeout finished before shutdown procedures finished, exiting program")
		os.Exit(1)
	}
}
