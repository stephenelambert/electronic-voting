# Minimum Viable Product (MVP)
This document describes the features required for a minimum viable product, and how this codebase implements the [design](design.md). Where it doesn't mention a part of the design that's in scope, the MVP implements it as the design describes.

## Major Features
The main major features to demonstrate in an MVP for this system are:
1. Trust chain from the root system signer all the way to the votes
2. Elections
    1. Blind signatures
    2. Auditability
3. Authorization of voters

## Specific Features
1. Register and Login
1. Create an Admin Account
1. Create jurisdiction
1. View jurisdictions
1. View single jurisdiction
1. Authorize voters
1. Create election
1. View elections
1. View single election
1. Voting
1. Process votes/results
1. View results
1. Verify a vote is counted (hash tree)
1. Audit election results
1. Audit election creation
1. Audit jurisdiction creation
1. Audit voter authorization

# Differences From the Design
- Global admins are the only admins, and there are no registrars. Everything the design lets registrars and jurisdiction admins do takes a global admin's certificate instead (see API), including publishing results, and only global admins see voters' details.
- Each endpoint accepts exactly one role and jurisdiction, so a client never has to choose which of its certificates to sign under.
- Global admins come from the server's config (see Admin Setup), rather than being added by other global admins. So no signed request authorizes their certificates, and their chain ends at the root. Each one would be an anchor of its own, and a restart with a different `ADMIN_USER` adds another.
- None of Pinning the Anchor (see the [design](design.md)) is built. Browsers only check that the root issued the certificate a request was signed under, and show the signer's fingerprint, so a global admin certificate the API's host issued to a key of its own would only be caught by someone who knows the real admins' fingerprints.
- Jurisdictions have no sub-jurisdictions, so a voter's jurisdiction is always the election's.
- There's no deauthorization, so nothing revokes a certificate, and browsers don't check certificates' validity dates or revocations.
- Jurisdictions, elections and candidates can't be changed, removed or canceled once they're created, so there's no history of changes for audits to cover.
- There are no external ballot boxes or external elections, write-ins, images, system-wide settings, or 2FA.
- Recovery record uploads don't include the election key's `public_key_hash` (see Casting a Vote in the [design](design.md)), so the API doesn't check which key a record was blinded under, and the record's request doesn't say.
- The file of published votes is built in memory. Very large elections would need it streamed instead.

# Known Limits
These are on top of the design's own known limits (see Known Limits in the [design](design.md)).
- The frontend only calls the API on its own origin (`/api`), and the API doesn't support cross-origin requests, so both have to be served from the same origin. That puts the frontend's code in the hands of the API's host, which could serve a version that skips browsers' checks or sends itself users' passwords and keys. So the checks don't protect against the API's host until the frontend is served separately (see Trust Chain and Audit Limits in the [design](design.md)).
- Once a user logs in or registers, their private key and AES key are kept unencrypted in the browser: in localStorage if they chose "remember me", or in sessionStorage otherwise. Anyone who can read that storage, like a script injected into the page or someone with access to the device, can sign requests as the user and decrypt their recovery records, which show how they voted. So ballot secrecy depends on the browser's storage as well as the password (see Authentication Limits in the [design](design.md)).
  - Possible mitigation: keeping the keys in IndexedDB as non-extractable CryptoKeys, so a script running in the page could use them but not copy them out.
- Login attempts aren't rate limited, so online guessing is only slowed by the Argon2id run in the client for each attempt.
- Unknown usernames get a 401 from `login/start` and taken ones a 409 from `register/start`, so which usernames exist isn't hidden.
- Election keys that no election claims are never deleted. The election form asks for its key (`election_key.create`) on its first submit, and creating the election claims it, so a form given up on after a failed submit leaves an unclaimed key behind.
  - Possible mitigation: deleting keys that are still unclaimed a day after they're created.
- The API doesn't cap an election's `time_open` and `time_close`, but browsers reject times of 2^53 or more, which JavaScript can't hold exactly. So an admin could create an election that fails every browser's check, though the design has the API refuse anything browsers would reject (see Auditing the System in the [design](design.md)).
- If the browser is still loading an election's published results, or couldn't load and check them, "Check my vote" checks the vote against every published vote instead of a proof, downloading all of them without asking (see Checking a Vote in the [design](design.md)).

# Implementation

## Authentication
- The configuration is ristretto255 with SHA-512, for the OPRF and the 3DH key exchange. The API uses `github.com/bytemare/opaque` and the browser uses `@serenity-kit/opaque`, and both versions are pinned.
- Passwords are stretched with Argon2id (64 MiB, 3 passes, 4 lanes), which only runs in the browser. Changing the settings means every account has to register again.
- OPAQUE's input is the JSON array `["electronic-voting/opaque/v1", username, password]`, with the password NFC normalized so it matches however it's typed. The browser trims usernames.
- The server's OPAQUE identity is its public key (the default).
- The export key is put through HKDF-SHA-256 (info `electronic-voting/aes-key-wrap/v1`) for the AES-GCM key that encrypts the account's AES key.
- Registering takes two requests. `POST /api/v1/register/start` answers the client's registration request, and `POST /api/v1/register` stores the client's registration record along with the account's keys.
- Logging in takes two requests too. `POST /api/v1/login/start` answers the client's KE1 with KE2 and a login ID, and keeps the MAC the client's KE3 must hold for 60 seconds. `PUT /api/v1/login` checks the KE3, and only then returns the account's encrypted keys. A wrong password fails in the browser, which then sends nothing more.

## Certificates
- Certificates are valid until the end of 9999, which RFC 5280 uses for certificates with no well-defined expiration date.
- A small DER parser in the browser reads the certificates. It only accepts certificates in the form the API issues, and WebCrypto checks their signatures.

## Exact Encodings
Votes and hash tree counts each have one accepted encoding, as request bodies do (see Signed Requests). The API checks them the same way, by re-encoding what it parsed and comparing bytes, and browsers check votes and counts that way too.

## Publishing Votes
Each election's vote counter (see Election Vote Counters) is created with the election, in the same transaction. Casting increments it in the vote's transaction, just before inserting the vote, which keeps the counter's row locked until the vote commits. It reads back whether the election is open by the database's clock, rather than each server's, since the clocks of several API servers can disagree, and rejects the vote if it isn't.

Closing an election freezes its count, which publishes its votes:
- Every request for the vote summary, the published votes or the blind-signature requests tries to set the counter's final flag, which only works once the election has closed by the database's clock, so the first such request after the close sets it. Until then, trying does nothing and waits for nothing.
- Setting it waits for any vote still being cast, since each holds the counter's row until it commits. Casting reads the flag back when it increments the count, and rejects the vote if it's set. So once the flag is set, every vote is in, and the published votes never change.

The file of published votes isn't stored anywhere. It's built from the Votes table whenever it's requested, in a fixed format, so it's the same bytes every time. The tally is counted from the Votes table the same way, so casting never touches it.

## Hash Tree
The tree is built in the same request that publishes the results, holding the election's vote counter row so requests to publish run one at a time, and the number of votes in it has to match the counter. A rejected request rolls the tree back, and it's built the same way next time.
Publishing needs the counter to be final already, rather than setting the flag itself, since that would hold the counter's row until the tree was built, and every request for the summary or the votes would wait. The admin's client sets it by downloading the votes.

# Running the API

## Server Secrets
The OPRF seed and the database key are read in base64 from environment variables, never from command-line flags, and the API won't start without valid ones. Back each one up separately from the database.
- The OPRF seed is 64 random bytes, in `OPAQUE_OPRF_SEED` (generate one with `openssl rand -base64 64 | tr -d '\n'`). It's kept out of the database, so a copy of the database alone can't be used to check password guesses. Without it, nobody can log in, and every account's keys are lost. Nothing checks that it's the seed the accounts registered with: with another one, the API starts, but every login fails as if the password were wrong.
- The server's OPAQUE key pair is stored in the database (see OPAQUE Server Key), and created when the API starts if no account has registered yet. Every registration record depends on it, so if it's missing once accounts have registered, the API won't start.
- The database key is 32 random bytes, in `DB_ENCRYPTION_KEY` (generate one with `openssl rand -base64 32`). It encrypts the private keys in the database with AES-256-GCM (see `backend/util/dbcrypt`): the system signing key, election keys and the OPAQUE server key, along with accounts' keys, which their clients have already encrypted. So a copy of the database alone doesn't reveal them. Without it, every private key in the database is lost, and with another key, the API won't start, since it can't decrypt the system signing key.
  - Encrypted values aren't tied to their rows, so the key doesn't protect against someone who can write to the database. They could make the system signing key belong to their account, for example, so logging in returns it.

## Admin Setup
When it starts, the API creates the global admin account named by `ADMIN_USER`, unregistered, with the hash of `ADMIN_SETUP_TOKEN`, which has to be at least 16 characters (generate one with `openssl rand -base64 24`). Whoever registers that username with the token as their registration token claims the account and gets its global admin certificate. Until then, starting with a different token replaces the old one.
- If two registrations send the token at once, like a form submitted twice, only one claims the account. The other gets a 409, as does a wrong or missing token, the same as for a taken username.
- `register/start` answers an unclaimed account like a free username, so it can be told apart from a registered one, but it can't be claimed without the token.

# API

## Signed Requests
Clients send a signed request's timestamp, public key, role, jurisdiction and signature (see Request Authentication for API in the [design](design.md)) in the Authorization HTTP header, period delimited (like a JWT):

```
Bearer <timestamp>.<public key>.<role>.<jurisdiction>.<signature>
```

- The public key is base64-encoded PEM, and the signature is base64.
- The timestamp must be within 5 seconds of the API's clock.
- A body's one accepted encoding is canonical JSON: the fields in the order of the API's request type, no whitespace, and strings escaped the way JavaScript's `JSON.stringify` escapes them, except that U+2028 and U+2029 are escaped too, since Go's encoder always escapes them. The API checks this by re-encoding the parsed body and comparing bytes. Go's parser ignores unknown fields and matches field names whatever their case, and browsers' doesn't, so without the check the two could read the same body differently.

## Actions
These take a signed request (see Request Authentication for API in the [design](design.md)) under a certificate for the role shown. The design lets more roles make most of them.

| Action | Endpoint | Role |
| ------ | -------- | ---- |
| `account.search` | `GET /api/v1/accounts` | global admin |
| `certificate.list_own` | `GET /api/v1/certificates/my` | none |
| `jurisdiction.create` | `POST /api/v1/jurisdictions` | global admin |
| `voter.authorize` | `POST /api/v1/jurisdictions/{id}/voters` | global admin |
| `voter.list` | `GET /api/v1/jurisdictions/{id}/voters` | global admin |
| `election_key.create` | `POST /api/v1/jurisdictions/{id}/election-keys` | global admin |
| `election.create` | `POST /api/v1/jurisdictions/{id}/elections` | global admin |
| `recovery_record.create` | `POST /api/v1/elections/{id}/recovery-record` | voter in the election's jurisdiction |
| `recovery_record.read` | `GET /api/v1/elections/{id}/recovery-record` | none |
| `blind_signature.request` | `POST /api/v1/elections/{id}/blind-signatures` | voter in the election's jurisdiction |
| `results.publish` | `POST /api/v1/elections/{id}/results` | global admin |

## Unauthenticated Endpoints
- `POST /api/v1/register/start` and `POST /api/v1/register` register an account, and `POST /api/v1/login/start` and `PUT /api/v1/login` log in (see Authentication).
- `GET /api/v1/certificates/root` serves the root certificate and its public key.
- `GET /api/v1/jurisdictions` lists the jurisdictions, and `GET /api/v1/jurisdictions/{id}/elections` lists a jurisdiction's elections.
- `GET /api/v1/jurisdictions/{id}` and `GET /api/v1/elections/{id}` include the request that created the jurisdiction or election, as `signed_request`, and so do the responses to the requests that create them. Lists of jurisdictions and elections leave it out.
- `GET /api/v1/jurisdictions/{id}/voter-authorizations` lists the jurisdiction's voter authorizations, in the order they were issued: each active voter certificate (`certificate`) with the admin's request that authorized it (`authorization`). Voters are named by their keys, not their usernames, so anyone can count a jurisdiction's voters and check that an admin authorized each one.
- `POST /api/v1/elections/{id}/votes` casts a vote (see Casting a Vote in the [design](design.md)).
- `GET /api/v1/elections/{id}/votes/summary` gives the number of votes cast and whether every vote is published, and once they are, the tally: the candidates on the ballot in ballot order, then any other candidate IDs that votes named. It's cached for 10 seconds, since the count changes with every vote.
- `GET /api/v1/elections/{id}/votes/published` gives every vote once the election has closed, ordered by nonce so users can count locally: one JSON object per line, with the nonce, the vote (as a string, so its exact bytes survive) and the signature, in that order. It never changes once it's published, so it can be cached forever. Before then it's a 404, sent with `Cache-Control: no-store` so no cache keeps it.
- `GET /api/v1/elections/{id}/blind-signature-requests` lists every voter's request for a blind signature in the election, in the order they were signed, each with the request that authorized the voter (`signed_request` and `authorization`). It's published with the votes, with the same 404 before then, so nobody can see who has voted while the election is open. Unlike the votes, it isn't cached forever, since blind signatures stop by the API server's clock rather than the database's: a server whose clock is behind can still sign after the votes are published, though no vote can be cast with the signature.
- `GET /api/v1/elections/{id}/results` serves the request that published the election's results (see Publishing the Root in the [design](design.md)), and is a 404 until the results are published.
- `GET /api/v1/elections/{id}/votes/{nonce}/proof` gives the proof for the vote with that nonce (see Checking a Vote in the [design](design.md)).

Whenever the API returns a stored request, it includes the certificate the request was signed under (`cert_pem`), so its signer can be checked.

Recovery records, blind signatures, votes and results get a 201 when they're first stored, and a 200 when the same one is sent again. A different one where one is already stored, like a second blinded message from a voter or a different vote with a nonce already cast, gets a 409.

# Tables

These are the tables [the migration](../backend/migrations/1_0.1.sql) creates. Where a table's purpose is part of the design, it's described under the same heading in the [design](design.md). Unless otherwise specified, all IDs are UUIDs.

## Accounts

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | UUID to identify account |
| username | String | Username of the user. |
| opaque_record | Bytes | The account's OPAQUE registration record (see Authentication), or NULL until the account is registered, like the admin account the API creates |
| setup_token_hash | Bytes | SHA-256 hash of the token that claims an admin account the API created (see Admin Setup), or NULL once it's registered |
| aes_key | String (base64) | Key for most AES encryption, encrypted by a key derived from the OPAQUE handshake export key, or empty until the account is registered |
| is_admin | Boolean | Whether this is the global admin account the API creates (see Admin Setup) |

User's public and (encrypted) private key can be found in the signing_keys table.

A username can be anything that isn't empty and doesn't start or end with whitespace (see Authentication in the [design](design.md)).

## OPAQUE Server Key

The server's OPAQUE key pair (see Server Secrets). There's only ever one row.

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| singleton | Bool | Always true, so there can only be one row |
| private_key | Bytes | The encoded ristretto255 private key, encrypted with the database key (see Server Secrets) |
| public_key | Bytes | The encoded ristretto255 public key, which is also the server's OPAQUE identity |
| creation_timestamp | Int | Unix timestamp of creation |

## Pending Logins

Logins between the server's KE2 and the client's KE3 (see Authentication). Each one can only finish once. A check that fails is rolled back with the rest of its request, so the login can still be finished until it expires, but a KE3 can't be guessed. Expired ones are deleted whenever a login starts.

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | The login ID the client finishes the login with |
| account_id | UUID/String | FK(Accounts) The account logging in |
| expected_client_mac | Bytes | The MAC the client's KE3 must hold |
| creation_timestamp | Int | Unix timestamp of when the login started. It expires 60 seconds later |

## Certificates

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id for the certificate. |
| serial_number | String | Serial number of the x.509 certificate (hex, unique). |
| pub_pem | String | FK to signing_keys table (public_key), PEM of the signing key's public key. |
| cert_pem | String | PEM of the x.509 certificate. |
| not_before | Int | Valid date of the certificate. |
| not_after | Int | Expiration of the certificate. |
| signer_cert_id | String | FK (to same table) of certificate used to sign, null if self-signed. |
| jurisdiction_id | String | FK to jurisdiction. |
| role | String | The role for the certificate: `system` (the self-signed root), `global_admin`, `jurisdiction_admin`, `registrar` or `voter`. The MVP only issues `system`, `global_admin` and `voter` certificates. |
| crl | String | PEM of the CRL, once revoked. |
| creation_timestamp | Int | Timestamp of creation. |
| revocation_timestamp | Int | Timestamp of revocation. |
| revocation_reason | String | Optional reason for why the cert was revoked. |
| signed_request_id | UUID/String | FK(Signed Requests) The signed request that authorized the certificate, like an admin's voter authorization. Null for the root, and for global admins, which come from the server's config. Voter authorizations are published for auditing, with the voters' keys but not their usernames. |

A unique index allows one unrevoked certificate for each key, role and jurisdiction.

## Voting Jurisdictions

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id for the jurisdiction. |
| name | String | Name of the jurisdiction, unique on the instance |
| info | String | identifying information (location) |
| created_timestamp | Int | Unix timestamp of creation |
| signed_request_id | UUID/String | FK(Signed Requests) The admin's signed request that created the jurisdiction, which is published for auditing |

## Election

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id for the election. The client generates it, so the request it signs covers it. |
| title | String | Title of the election |
| description | String | Description for the election |
| jurisdiction_id | UUID/String | FK(Voting Jurisdictions) The Jurisdiction for which this election is taking place |
| time_open | Int | Unix timestamp for when this election should start |
| time_close | Int | Unix timestamp for when this election should end, which has to be after time_open |
| public_key | String | FK(Signing Keys) public key PEM of key used to sign for this election |
| created_timestamp | Int | Unix timestamp of creation |
| signed_request_id | UUID/String | FK(Signed Requests) The admin's signed request that created the election, which is published for auditing. Its body includes the election key and variant, which certifies the key for the election. |

The election key's `public_key_hash`, which blind-signature requests carry, isn't stored. The API works it out from public_key.

## Candidates

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id for the candidate. The client generates it, so the request it signs covers it. |
| name | String | The name of the candidate or option. |
| description | String | Description of the candidate or option |
| election_id | UUID/String | FK(Elections) Id of the election this candidate is for |
| position | Int | Position in the candidate list for the election: the candidate's index in the request that created the election |

A unique index exists for election_id and position.

## Blinded Signed Votes

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id of the blind signed vote |
| election_id | UUID/String | FK(Elections) Id of the election |
| blinded_message | String(base64) | Blinded vote |
| account_id | UUID/String | FK(Accounts) Id of the account that made this vote |
| created_timestamp | Int | Unix timestamp of creation |
| signed_request_id | UUID/String | FK(Signed Requests) The voter's signed request for the signature, which is published for auditing |
| blind_signature | String(base64) | Signature of the blinded vote from the key for the election. |

A unique index exists for election_id and account_id, so each voter gets one blind signature per election.

## Vote Recovery Records

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id of the recovery record |
| election_id | UUID/String | FK(Elections) Id of the election |
| account_id | UUID/String | FK(Accounts) Id of the account the record belongs to |
| signed_request_id | UUID/String | FK(Signed Requests) The signed request that uploaded the record. Its body holds the encrypted record. |
| created_timestamp | Int | Unix timestamp of creation |

A unique index exists for election_id and account_id, and a record can't be replaced once written.

## Votes

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id of the vote |
| election_id | UUID/String | FK(Elections) Id of the election |
| nonce | String(hex) | The 32 random bytes RFC 9474 adds to the front of the vote, as lowercase hex so it sorts in byte order. Voters find their vote by it. |
| raw | String | The vote JSON, exactly as signed |
| candidate_id | UUID/String | Id of the candidate, taken from the vote. Don't make a foreign key, as it may be for an external election, or for an ID that isn't on the ballot (see Vote Format in the [design](design.md)). |
| signature | String(base64) | Signature from the election key over the nonce followed by the raw vote |
| tree_position | Int | The vote's position when the election's votes are sorted by nonce (starting at 0), set when the hash tree is built, so later queries never re-sort the votes |

Unique indexes exist for election_id and nonce, and for election_id and tree_position.
The nonce index uses a byte-order collation (such as C in Postgres), so the database sorts nonces the same way the hash tree does.

## Election Vote Counters

Election Vote Counters hold the number of votes cast in each election so far, and whether the count is final, which is when the election's votes are published (see Publishing Votes and Hash Tree for how they're used).
They're kept apart from Election Results, since a result is written once and never changes, while a counter changes with every vote.

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| election_id | UUID/String | FK(Elections) Id of the election, and the primary key |
| votes_cast | Int | Number of votes cast in the election so far |
| final | Boolean | Set once the election has closed by the database's clock and every counted vote has committed, after which no vote can be counted (see Publishing Votes) |

## Signing Keys

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id for the key |
| private_key | Bytes | Private key for the key pair, encrypted with the database key (see Server Secrets). An account's key is encrypted by its client first |
| public_key | String | Public key (PEM, Unique constraint) |
| owner_type | String | What owns the key: `account`, `system` (the root) or `election` |
| owner_id | String | ID of the account or election that owns the key |
| creation_timestamp | Int | Unix timestamp of creation |
| deactivation_timestamp | Int | Unix timestamp of deactivation |

## Signed Requests

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id of the signed request |
| action | String | What the request does, like `voter.authorize` |
| instance | String(base64) | The instance the request was signed for: SHA-256 hash of its root certificate's public key |
| role | String | Role of the certificate the signer acted under, if the request needed one |
| jurisdiction_id | UUID/String | Jurisdiction of that certificate, if it has one. Not a foreign key, since certificate_id references the certificate. |
| request_timestamp | String | Timestamp from the Authorization header, exactly as signed |
| body | String | Request body, exactly as signed |
| public_key | String | FK(Signing Keys) public key PEM of the key that signed the request |
| signature | String(base64) | Signature of the request |
| certificate_id | UUID/String | FK(Certificates) The certificate the role and jurisdiction name, if any |

Not every signed request is public: each table that references this one says whether its requests are published.

## Hashes

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| election_id | UUID/String | FK(Elections) The ID for the election. |
| first_leaf | Int | Position of the first vote under this node, in nonce order (starting at 0). |
| leaf_count | Int | Number of votes under this node (1 for a leaf). |
| counts | String | Votes for each candidate ID under this node, in the design's encoding (see Hashes in the [design](design.md)), exactly as it goes into the hash. |
| hash_value | String(base64) | The node's hash, as the design describes. |

The primary key is election_id, first_leaf and leaf_count, which is how the server fetches the nodes a response needs.
A node's children, parent and height follow from first_leaf and leaf_count, so they aren't stored.
A vote's leaf is the node whose first_leaf is the vote's position (from Votes) and whose leaf_count is 1.
Storing counts as their JSON text rather than an array keeps the table to widely supported SQL types, and stores exactly what is hashed.

## Election Results

| Field Name | Type | Description |
| ---------- | ---- | ----------- |
| id | UUID/String | Id of the result |
| election_id | UUID/String | FK(Elections) Id of the election |
| vote_count | Int | Number of votes in the election. The root of its hash tree is the node with first_leaf 0 and this leaf_count. |
| signed_request_id | UUID/String | FK(Signed Requests) The admin's signed request publishing the root's hash and the tally, which is published for auditing |
| created_timestamp | Int | Unix timestamp of creation |

A unique index exists for election_id, so an election has one published result.
The vote count is stored so that requests don't need to count the election's votes.
