# electronic-voting

## Description
This electronic voting system aims to be a secure method of voting, where individuals can cryptographically verify that their vote has been counted while somewhat preserving the privacy of the votes.

The main purpose of this repository is to present the idea of using blind-signed votes that can be provably included in the final tally for an election, with the hope that ideas in this system can inspire someone who is better at designing secure voting systems than I am.
The design of the system, including [where it falls short](docs/design.md#where-it-falls-short), can be found in [the design doc](docs/design.md), and the repository itself includes something between a proof of concept and a minimum viable product, documented in the [MVP doc](docs/mvp.md).

The code is nothing particularly fancy, and I wouldn't recommend trying to set it up for any production use case.
Many protections offered by the full design are not covered by the current implementation. Most importantly, the API's host also serves the frontend, and browsers don't pin the instance's anchor yet, so the browser's checks don't protect against a dishonest API host (see [Differences From the Design](docs/mvp.md#differences-from-the-design) and [Known Limits](docs/mvp.md#known-limits) in the MVP doc).

## Running
Prerequisites:
- Go 1.27.3 or later, the version in `backend/go.mod`. Go 1.21 or later downloads it automatically.
- Node.js 20.19+, 22.13+ or 24+, for the frontend
- A Postgres 17 server running and accessible
  - `make launch-db`, run from this directory, starts one in Docker with the settings the API uses by default. `make stop-db` stops it, and `make remove-db` removes it, so the next `make launch-db` starts with an empty database.

### Development
To run for development, the API and frontend are run separately.

To run the API, `cd` into the `backend/main` directory and run `go build -o api` to build the API.
Once the API is built, it can be run with `./api` to use the default parameters, with these environment variables set:
- `OPAQUE_OPRF_SEED`: the OPRF seed for password logins, which the API won't start without. Generate it once with `openssl rand -base64 64 | tr -d '\n'` and keep it, since accounts can't log in with any other seed (see Server Secrets in the [MVP doc](docs/mvp.md)).
- `DB_ENCRYPTION_KEY`: the key that encrypts the private keys in the database, which the API won't start without. Generate it once with `openssl rand -base64 32` and keep it, since the API can't read its keys with any other key (see Server Secrets in the [MVP doc](docs/mvp.md)).
- `ADMIN_USER` and `ADMIN_SETUP_TOKEN`: the global admin's username, and the token that claims it when it's registered (generate one with `openssl rand -base64 24`; see Admin Setup in the [MVP doc](docs/mvp.md)).

The API listens on port 5172, which is where the frontend's development server sends API requests. It connects to the database with these environment variables, which default to the settings `make launch-db` uses. Each also has a command-line flag, which `./api -help` lists.
- `DB_HOST` and `DB_PORT`: the database's host and port, `localhost` and `5432` by default
- `DB_USER` and `DB_PASS`: the user to connect as and its password, `postgres` and `password` by default
- `DB_NAME`: the database, `postgres` by default

When it starts, the API runs any migrations in `backend/migrations` that the database hasn't run yet. While in early development, schema changes edit `1_0.1.sql` in place, so after a change, the API won't start against a database set up with the old version: it stops with `migration file '1_0.1.sql' was modified after being previously applied`. `make remove-db launch-db` replaces the database with an empty one.

To run the frontend, run `npm install` and then `npm run dev` from the `frontend` directory, and open the address it prints (`http://localhost:5173` by default). Its [README](frontend/README.md) lists the other scripts.

To test the API, run `go test ./...` from the `backend` directory. `make lint-api` lints it with golangci-lint, in Docker.

## Usage
To try a whole election once the API and frontend are running:
1. Sign up as `ADMIN_USER`, with `ADMIN_SETUP_TOKEN` in the "Registration Token" field.
2. As the admin, create a jurisdiction from the Jurisdictions page.
3. In a private window or another browser, sign up a voter account. As the admin, authorize it from the jurisdiction's Voters page.
4. As the admin, create an election from the jurisdiction's Elections page. It has to open in the future, so have it open in a minute or two and close a few minutes later.
5. Once the election opens, vote as the voter from its page. You may need to refresh the page to see the "Vote" button.
6. Once it closes, publish the results as the admin from the election's page. The voter can then check that their vote is counted with "Check my vote", and anyone can audit the election with "Audit every vote and signature request".

## Project status
I don't really plan to work much more on this project, but I may if there's some actual interest.
It's just been an insect in the back of my mind for a few years, and I felt compelled to get it into code and put it out there.

## Contributing
Since I don't really plan to work much more on this project, if you're looking to mess around with it and make changes I'd recommend forking it.

## Authors and acknowledgment
I came up with the idea and wrote the initial documentation, skeleton, and first few features on my own, but eventually started using Claude Code to accelerate the development and refine and expand the documentation on the design.

## License
Licensed under the MIT License; see [LICENSE](LICENSE).
