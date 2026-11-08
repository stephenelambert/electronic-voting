CREATE TABLE signing_keys(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- encrypted with the database key (see dbcrypt). An account's key is encrypted by its client
    -- first
    private_key BYTEA NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    owner_type TEXT NOT NULL CHECK(owner_type IN ('account', 'system', 'election')),
    owner_id UUID,
    creation_timestamp BIGINT NOT NULL,
    deactivation_timestamp BIGINT
);

CREATE INDEX ON signing_keys(owner_type, owner_id);

-- authenticated requests, stored exactly as they were signed so their signatures can be checked
-- again later. tables that reference a request decide whether it is published
CREATE TABLE signed_requests(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- what the request does, like voter.authorize
    action TEXT NOT NULL,
    -- the instance the request was signed for: the base64 SHA-256 hash of its root certificate's
    -- public key
    instance TEXT NOT NULL,
    -- the role and jurisdiction of the certificate the signer acted under, if the request needed
    -- one. certificate_id references that certificate, so the jurisdiction needs no foreign key
    role TEXT,
    jurisdiction_id UUID,
    request_timestamp TEXT NOT NULL,
    body TEXT NOT NULL,
    public_key TEXT NOT NULL REFERENCES signing_keys(public_key),
    signature TEXT NOT NULL,
    -- its foreign key is added after certificates, since certificates reference signed requests too
    certificate_id UUID
);

CREATE TABLE voting_jurisdictions(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    info TEXT NOT NULL,
    name TEXT NOT NULL UNIQUE,
    created_timestamp BIGINT NOT NULL,
    -- the admin's signed request that created the jurisdiction
    signed_request_id UUID NOT NULL REFERENCES signed_requests(id)
    --parent_id UUID REFERENCES voting_jurisdictions(id) ON DELETE CASCADE
);

CREATE TABLE certificates(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    serial_number TEXT NOT NULL UNIQUE,
    pub_pem TEXT NOT NULL REFERENCES signing_keys(public_key),
    cert_pem TEXT NOT NULL,
    not_before BIGINT NOT NULL,
    not_after BIGINT NOT NULL,
    signer_cert_id UUID REFERENCES certificates(id),
    jurisdiction_id UUID REFERENCES voting_jurisdictions(id),
    role TEXT NOT NULL CHECK (role IN ('global_admin', 'system', 'jurisdiction_admin', 'registrar', 'voter')),
    crl TEXT,
    creation_timestamp BIGINT NOT NULL,
    revocation_timestamp BIGINT,
    revocation_reason TEXT,
    -- the signed request that authorized the certificate, like an admin's voter authorization. NULL
    -- for the root, and for global admins, which come from the server's config
    signed_request_id UUID REFERENCES signed_requests(id)
);

ALTER TABLE signed_requests ADD FOREIGN KEY (certificate_id) REFERENCES certificates(id);

CREATE UNIQUE INDEX certificates_active_role_unique
    ON certificates(pub_pem, role, jurisdiction_id) NULLS NOT DISTINCT
    WHERE revocation_timestamp IS NULL;

-- supports listing and counting a jurisdiction's active certificates for a role
CREATE INDEX ON certificates(jurisdiction_id, role)
    WHERE revocation_timestamp IS NULL;

CREATE TABLE accounts(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    -- the account's OPAQUE registration record (RFC 9807). It's NULL until the account is
    -- registered, like the admin account the API creates at startup
    opaque_record BYTEA,
    -- SHA-256 hash of the token that claims an admin account the API created. It's cleared once the
    -- account is registered
    setup_token_hash BYTEA,
    -- the account's AES key, encrypted by a key only its client can derive. It's empty until the
    -- account is registered
    aes_key TEXT NOT NULL,
    -- whether this is the global admin account the API creates at startup
    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);

-- supports case-insensitive username prefix searches
CREATE INDEX ON accounts(lower(username) text_pattern_ops);

-- the server's OPAQUE key pair (ristretto255). There's only ever one row, and every registration
-- record depends on it, so it can't be replaced without every account registering again
CREATE TABLE opaque_server_key(
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    -- encrypted with the database key (see dbcrypt)
    private_key BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    creation_timestamp BIGINT NOT NULL
);

-- logins between the server's KE2 and the client's KE3: the MAC the client's KE3 must hold. Each is
-- used once, and expired ones are deleted when a login starts
CREATE TABLE pending_logins(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expected_client_mac BYTEA NOT NULL,
    creation_timestamp BIGINT NOT NULL
);

CREATE INDEX ON pending_logins(creation_timestamp);

CREATE TABLE elections(
    -- election and candidate ids have no default: the client generates them, so the request it
    -- signs covers them
    id UUID PRIMARY KEY,
    jurisdiction_id UUID NOT NULL REFERENCES voting_jurisdictions(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    time_open BIGINT NOT NULL,
    time_close BIGINT NOT NULL CHECK (time_close > time_open),
    -- the election key, referenced by its public key (like certificates.pub_pem) since that is how
    -- the signed request that created the election names it
    public_key TEXT NOT NULL UNIQUE REFERENCES signing_keys(public_key),
    created_timestamp BIGINT NOT NULL,
    -- the admin's signed request that created the election, which certifies its key
    signed_request_id UUID NOT NULL REFERENCES signed_requests(id)
);

-- supports listing a jurisdiction's elections, most recent first
CREATE INDEX ON elections(jurisdiction_id, time_open DESC);

-- how many votes have been cast in each election. Casting increments it just before inserting the
-- vote, so its row stays locked until the vote commits. final is set once the election has closed by
-- the database's clock and every counted vote has committed, after which no vote can be counted, so
-- the election's votes can be published
CREATE TABLE election_vote_counters(
    election_id UUID PRIMARY KEY REFERENCES elections(id),
    votes_cast BIGINT NOT NULL DEFAULT 0,
    final BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE candidates(
    id UUID PRIMARY KEY,
    election_id UUID NOT NULL REFERENCES elections(id),
    -- ballot order: the candidate's index in the request that created the election
    position INT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE (election_id, position)
);

-- what a voter's client needs to finish casting its vote from any device, encrypted by the client.
-- the request that uploaded the record holds it in its body, and is only returned to its owner
CREATE TABLE vote_recovery_records(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id UUID NOT NULL REFERENCES elections(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    signed_request_id UUID NOT NULL REFERENCES signed_requests(id),
    created_timestamp BIGINT NOT NULL,
    -- records can't be replaced, since a signature may already have been issued for one
    UNIQUE (election_id, account_id)
);

-- votes the election key has signed blind, each with the voter's request for the signature, which
-- is published for auditing
CREATE TABLE blinded_signed_votes(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id UUID NOT NULL REFERENCES elections(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    blinded_message TEXT NOT NULL,
    signed_request_id UUID NOT NULL REFERENCES signed_requests(id),
    blind_signature TEXT NOT NULL,
    created_timestamp BIGINT NOT NULL,
    -- each voter gets one vote signed per election
    UNIQUE (election_id, account_id)
);

-- cast votes. there is deliberately no timestamp: when a vote arrived could link it to the voter's
-- request for its signature
CREATE TABLE votes(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id UUID NOT NULL REFERENCES elections(id),
    -- lowercase hex, with the C collation so nonces sort in byte order, like the hash tree's leaves
    nonce TEXT COLLATE "C" NOT NULL,
    -- the vote JSON, exactly as signed
    raw TEXT NOT NULL,
    -- not a foreign key, since the vote may be for an external election
    candidate_id UUID NOT NULL,
    signature TEXT NOT NULL,
    -- the vote's position when the election's votes are sorted by nonce (starting at 0), set when the
    -- hash tree is built
    tree_position BIGINT,
    UNIQUE (election_id, nonce),
    UNIQUE (election_id, tree_position)
);

-- the nodes of each election's hash tree, built when its results are published. a node covers
-- leaf_count votes starting at position first_leaf, which is all that's needed to find its children
-- and parent
CREATE TABLE hashes(
    election_id UUID NOT NULL REFERENCES elections(id),
    first_leaf BIGINT NOT NULL,
    leaf_count BIGINT NOT NULL,
    -- the votes for each candidate ID under the node, exactly as they are hashed
    counts TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    PRIMARY KEY (election_id, first_leaf, leaf_count)
);

-- each election's published results: the admin's signed request publishing the root of its hash
-- tree and its tally, which is published for auditing. it's written with the hash tree and never
-- changes
CREATE TABLE election_results(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id UUID NOT NULL UNIQUE REFERENCES elections(id),
    -- the root of the election's hash tree is the node with first_leaf 0 and this leaf_count
    vote_count BIGINT NOT NULL,
    signed_request_id UUID NOT NULL REFERENCES signed_requests(id),
    created_timestamp BIGINT NOT NULL
);