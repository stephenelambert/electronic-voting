# Design

This describes the system as designed. What the MVP implements, and where it differs, is in [mvp.md](mvp.md).

# Overview

A voting system that can be used from just about anywhere, in a plain web browser, where anyone can check the count, and the server can confirm a voter is authorized without seeing how they voted. Each instance is one deployment of the API, with its own root key, accounts, jurisdictions and elections. The rest of this document has the detail behind each part of this overview.

## Requirements

- Only authorized people can vote
- Authorized people get exactly one vote in each election
- Anonymity
  - Others can't identify or prove your vote
  - Best if you can't prove your vote
- Auditable
  - Know your vote counted
  - Allow everyone to see the cast votes and count on their own

Known Limits lists where the design falls short of these requirements.

## Who Can Do What

Voting jurisdictions are nested areas, like a state and its counties. Registrars authorize accounts as voters in a jurisdiction, based on ID (potentially email at a later date), and a voter can vote in elections for their jurisdiction and the ones above it. Admins run the jurisdictions they're over: their elections, sub-jurisdictions and officials (see Roles).

Each role is a certificate for the user's key, and every one but the first global admin's is authorized by a signed request from someone allowed to grant it. Every other change, apart from casting a vote, is a signed request too. The authorizing requests and other ones later checks need are kept. The API's server issues the certificates, but browsers don't take its word for them: each one has to trace back through those requests to the first global admin's key, the anchor, which users pin (see Trust Chain for Everything).

Users log in with a password the server never sees, which unlocks their signing key and the key that encrypts what only they can read (see Authentication).

## How Voting Works

Each election has its own key, certified by the signed request that created it (see Election Keys). To vote, the voter's browser:
1. builds the vote with a random nonce, and blinds it so the server can't read it
2. uploads a recovery record that only the voter can decrypt, so they can finish or check their vote from any device
3. asks for the election key's signature on the blinded vote, in a request signed under their voter certificate, which each voter gets once per election
4. unblinds the signature, and casts the vote without logging in, so it isn't directly tied to their account

An instance can also receive votes for elections hosted elsewhere, so a host can't quietly drop votes it doesn't want counted, and, if every vote goes elsewhere, can't link a vote to its voter (see Mitigating Rigging of Elections By Controlling Parties).

## How Anyone Checks It

- Once an election closes, its votes are published with their signatures, so anyone can check each one and count them. Voters find their own by its nonce (see Publishing Votes).
- Voters' signed requests for blind signatures are published too, so anyone can check that the valid votes don't outnumber authorized voters who asked to vote (see Auditing the System).
- An admin publishes the tally with the root of a hash tree of the votes, so a voter can check that their vote is counted with a small proof, instead of downloading every vote (see Hashes).
- Browsers check the signed requests behind whatever they use, like an election's key before voting with it, and can audit a whole election or jurisdiction on request (see What Browsers Check).

## Where It Falls Short

These are covered in Known Limits:
- The server can usually link a vote to its voter through the network requests around casting it, and learn which vote a voter checks. Published blind-signature requests show which elections each voter's key voted in, though not how.
- With external ballot boxes, where a vote is sent shows how it was cast.
- A voter can prove how they voted, through their recovery record.
- Votes and results can't be checked until the election closes.
- The server can try to crack any account's password offline, and a cracked password lets it act as that user, including as an admin.
- The server holds each election's key, so it can add a vote for a voter who got a blind signature but didn't cast one. Casting has no receipt, so a voter can't show the server dropped their vote.
- The server could show different people different records.
- Browsers' checks are only as trustworthy as the frontend code that runs them, and pinning only helps users who compare the anchor's fingerprint.

# Authentication

Accounts register and log in with OPAQUE ([RFC 9807](https://www.rfc-editor.org/rfc/rfc9807)), so the API never receives a password, or anything it could check a password guess against without the OPRF seed.
- OPAQUE is given the username along with the password. RFC 9807 stretches with a fixed salt, so only each account's OPRF key keeps their stretched passwords apart, and clients can't check that the server gives each account its own. With the username in the input, a server that used one key for every account would still have to stretch each guess separately per account.
- The client's identity in OPAQUE is its username, which also picks the account's OPRF key. So usernames can't change, and they can't start or end with whitespace, since they have to be typed exactly the same every time.
- The session key OPAQUE agrees on isn't used, since requests are authenticated with signatures from the account's key instead.
- OPAQUE's export key, which only the client gets and which is the same at every login, derives the AES-GCM key that encrypts the account's AES key. The account's AES key encrypts everything only the user can view, so a password change only has to re-encrypt it.
- Each account has one key pair for signing requests. The server stores the public key, and the private key encrypted with the account's AES key.
  - This key is the subject key for all of the user's certificates.
  - It may be replaced, but replacing it requires a new certificate for every role.

# System Setup
1. A user is created as an initial global admin with a certificate, signed with a key generated by the server under a self-signed root certificate. Their key is the instance's anchor (see Pinning the Anchor).
2. Global admin creates a jurisdiction and authorizes other users as jurisdiction admin with certificates.
3. Jurisdiction admins manage jurisdictions by creating sub-jurisdictions, authorizing registrars with certificates, and creating elections.
4. Registrars for jurisdictions authorize users as voters in their jurisdictions with a certificate as their authorization.

## Roles

A registrar or jurisdiction admin holds their role for one jurisdiction, and is "over" that jurisdiction and every jurisdiction under it. Global admins are over every jurisdiction, and "an admin" means either kind of admin.
- Voters can vote in elections for their jurisdiction and the jurisdictions above it.
- Registrars authorize and deauthorize voters in the jurisdictions they're over.
- Jurisdiction admins can do anything a registrar can in the jurisdictions they're over. There, they also manage elections and their candidates, create and manage sub-jurisdictions, authorize and deauthorize registrars and other jurisdiction admins, and publish election results. They can also set up external ballot boxes (see External Ballot Boxes).
- Global admins can do anything a jurisdiction admin can, in every jurisdiction. They also create top-level jurisdictions and external elections (see Election), add and remove other global admins, and change system-wide settings.

Each role is granted by a certificate of its own (see Trust Chain for Everything), and each signed request names the role it acts under (see Request Authentication for API).

# Voting

## Election Keys

- Each election has its own 2048-bit RSA key, used only for RFC 9474 blind signatures with the RSABSSA-SHA384-PSS-Randomized variant.
- The server generates the election key, and the signed request that creates the election includes the key and the variant, which certifies the key for that election. There is no X.509 certificate for election keys.
- The variant adds 32 random bytes to the front of each vote before it is blinded. These bytes are the vote's nonce: they make every signed vote unique and let a voter find their vote later.

## Vote Format

The election key signs the vote's 32-byte nonce followed by the vote, which is JSON in exactly this form:

```json
{"version":1,"election_id":"<uuid>","candidate_id":"<uuid>"}
```

- Fields are in this order, with no whitespace and no other fields, and IDs are lowercase, hyphenated UUIDs.
  - The server signs votes blind, so casting and auditors' counts are the only places a vote's content is checked, and they need to agree on what is valid.
  - A single encoding also keeps every vote for a candidate identical apart from its nonce, so a client's formatting can't single out its users.
- `candidate_id` should be the ID of one of the candidates in the request that created the election. A vote in this form for any other ID is still valid: it's counted under its own ID, so it shows up in the tally as a candidate who isn't on the ballot rather than disappearing.
- Signatures are RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-byte salt, which is what RFC 9474 produces for this variant, so standard RSA-PSS verification can check them.
- Version 1 has no write-ins. A later version can add a `write_in` field for elections that allow them.

A vote is valid if:
1. its signature verifies under the election's key, over the nonce followed by the vote,
2. the vote is in exactly the form above,
3. its `election_id` is the election's ID,
4. and no other vote in the election has the same nonce.

The server also rejects votes cast while the election isn't open.

## Casting a Vote

1. The client builds the vote, adds the nonce (RFC 9474's Prepare step) and blinds the result under the election's key (Blind). Blinding gives the blinded message and `inv`, the value that later unblinds the signature.
2. Before asking for a signature, the client encrypts the nonce, vote, `inv` and blinded message with the user's AES key and uploads them as a recovery record, along with the election key's `public_key_hash` (unencrypted), in a separate signed request.
    1. There is one recovery record per voter per election, and it can't be replaced once written. If the upload fails, nothing has been signed yet, so the client can start over.
    2. The server keeps the upload's signed request, so it can show the record came from the user, but never publishes it. That's why the record isn't part of the blind-signature request, which is published for auditing.
    3. The server rejects the upload if the hash isn't the election key's, as it does for the blind-signature request. So the stored upload is the voter's signed statement of which key they blinded under, made before anything is signed. A server can't accept one for another key without knowing it, and a voter can't later claim a different key.
3. The client requests the blind signature: a signed request with the election's ID, the blinded message and the election key's `public_key_hash` (the base64 SHA-256 hash of the key's DER encoding), authenticated by the voter's certificate for the election's jurisdiction or one of its sub-jurisdictions.
    1. The server rejects the request if the election isn't open or the hash isn't the election key's.
    2. Each voter gets one blinded message signed per election. Sending the same blinded message again returns the stored blind signature, so a client that lost the response can ask again. A different blinded message is rejected.
    3. The server stores the signed request with the blind signature (see Blinded Signed Votes). Because the request includes the key's hash, a server that gave a voter a different key leaves signed evidence of it.
4. The client unblinds the signature with `inv` (Finalize), which also verifies it, so a bad response shows up right away.
5. The client casts the vote by sending the nonce, vote and signature to the receiving server. This request isn't authenticated, so the vote isn't directly tied to the voter's account (though see Anonymity Limits).
    1. Sending the same vote again succeeds, so a client that doesn't know whether its vote arrived can send it again.
    2. A different vote with the same nonce is rejected.

## Finishing or Verifying From Another Device

If casting is interrupted, the voter can finish from any device they log in on:
1. The client fetches the voter's recovery record for the election, along with the signed request it was uploaded in, and checks that the signature is the voter's own before decrypting.
    1. If the signature doesn't verify, the server altered the record.
    2. If it verifies but the record won't decrypt, the client that uploaded it was at fault.
2. The client decrypts the record and repeats steps 3 to 5 of Casting a Vote with the stored values. This is always safe, since signing the same blinded message returns the same blind signature and casting the same vote succeeds.

To verify their vote, the voter's client uses the nonce from the recovery record.
Votes are only published once the election closes (see Publishing Votes), so until then there's nothing to check against, but a voter who isn't sure their vote was cast can finish casting it again from the voting page.
Once the election closes, the client downloads every published vote and checks that its own is there, the same as it was cast, with a valid signature under the election's key. Everyone downloads the same file, so this tells the server nothing about which vote is the voter's.
Once the results are published, a typical voter checks a proof from the hash tree instead, which doesn't need every vote (see Hashes).

## Publishing Votes

Votes are only published once the election closes, all at once. Publishing them as they arrive would let anyone match each new vote against the timestamps on voters' blind-signature requests:
- Until the election closes, only the number of votes cast is public. The tally isn't, since one that changed with every vote would show how each vote was cast as it arrived. A server that only receives some candidates' votes, like an external ballot box (see External Ballot Boxes), doesn't show its count either, since it would be their running tally.
- Published votes don't include when they were cast, and are ordered by nonce rather than by when they arrived.
- Once the election closes, no more votes can be cast, and the published votes never change.

A later iteration of the design could publish votes during the election in batches of 1,000, so they can be checked before it closes (see Auditability Limits):
- Each vote's batch would be set from the count when it's cast, so a batch never narrows a vote down to the few cast in a quiet period.
- A voter's check would have to fetch whole batches, since the server can place a voter in their batch from their blind-signature request.
- A voter could copy a published nonce into a vote of their own, which the server would reject, leaving a validly signed vote that looks replaced. Telling that apart from a vote the server really replaced would need receipts for cast votes (see Trust Chain and Audit Limits).

Once the election closes, an admin publishes the results: the tally and the root of a hash tree of the votes (see Hashes).

## Hashes

Hashes are the nodes of a hash tree (a Merkle tree) over an election's votes, built when an admin publishes its results, once it has closed.
The tree lets a voter check that their vote is counted in the published tally with a small download (for a million votes, about 20 nodes), instead of downloading every vote.
It complements the file of all votes rather than replacing it: auditors still use the file to recount and to rebuild the tree, which is what shows the published root matches the votes.

### Building the Tree

- The leaves are the election's votes, sorted by the bytes of their nonces. A vote's position is its place in that order, starting at 0.
- A node is identified by the votes it covers: `leaf_count` votes, starting at position `first_leaf`. The root covers every vote, starting at 0. A node's children are its first k votes and the rest, where k is the largest power of two smaller than its `leaf_count`. A leaf is a node with a `leaf_count` of 1.
- Every node has counts: the number of votes for each candidate ID under it, encoded as one JSON object with a count for each candidate ID that has votes, keys sorted, with no whitespace and no zero counts, like `{"<id1>":1,"<id2>":4}`. A leaf counts 1 for its vote's candidate, and the root's counts are the tally.
- A leaf's hash is SHA-256 of `0x00`, the nonce, the signature and the vote JSON, in that order, using the nonce's and signature's raw bytes rather than their stored text. The nonce and signature have fixed lengths, so the vote can go last without a length prefix.
- An internal node's hash is SHA-256 of `0x01`, the length of the left child's counts as a 4-byte big-endian integer, the left child's counts, the length of the right child's counts, the right child's counts, the left child's hash and the right child's hash, in that order.
  - Each child's counts must be in the hash separately. Hashing only the node's total, as the original Merkle sum tree did, lets the server undercount while every voter's proof still checks out.
  - Counts vary in length, so each is prefixed with its length. Otherwise the same bytes could be split into the two children's counts in more than one way, and one hash could stand for two different sets of counts. The hashes have fixed lengths, so they need no prefix.
  - Clients and auditors only accept counts in exactly that encoding, since JSON parsers don't all read other encodings (like repeated keys) the same way.
- The tree's shape and the `0x00` and `0x01` prefixes follow the Merkle tree in RFC 9162, so an auditor rebuilds exactly the same tree.
- An election with no votes has no nodes. Its root's hash is SHA-256 of nothing, as in RFC 9162, and its counts are `{}`.

Counts work for single-choice votes (version 1), and would also work for score voting.
Some types of ranked voting would be harder, since nodes may need counts for up to `N!` orders of candidates (where N is the number of voted-for candidates).

### Publishing the Root

- An admin over the election's jurisdiction (see Roles) publishes the results with a signed request (`results.publish`), naming the election, the number of votes, the root's hash and the tally, which is the root's counts. The body is exactly this, with the fields in this order and no whitespace, and the server rejects any other encoding:

  ```json
  {"election_id":"<uuid>","vote_count":16,"root_hash":"<base64>","tally":"{\"<id1>\":9,\"<id2>\":7}"}
  ```

- Before signing, the admin's client checks every published vote the way an auditor would (each is a valid vote in the election with a valid signature, and they're in nonce order) and rebuilds the tree from them.
- The server builds its own tree from the published votes when the results are published, and rejects results that don't match it. So publishing also shows the server's tree is built from the votes it published. Results can't be replaced, but sending the same body again succeeds.
- The election key never signs the root. It signs whatever a voter blinds, so a voter could get it to sign a fake root.
- Clients check the signature on the results before trusting the root: that an admin over the election's jurisdiction signed the request under a certificate whose chain leads back to the pinned anchor (see Auditing the System), to publish results (`results.publish`), and that it has a valid body for the election.
  - Clients show when the results were signed using the request's own timestamp, which the signature covers, not the time the server says it stored them.

### Checking a Vote

- A client asks for the proof for its own vote's nonce in an unauthenticated request, so the server can learn which vote is the voter's (see Anonymity Limits).
- The response has the published vote with that nonce (its nonce, vote and signature), its position, and the sibling of every node on the path from its leaf to the root, each with its hash and counts: about 20 nodes for a million votes. The vote is included because the client needs its signature to hash the leaf, and the recovery record doesn't hold it.
- The client checks that the published vote is exactly its own, with a valid signature. If a different vote is published with its nonce, the election key signed two votes with the same nonce. The server could have signed the other one itself, but two voters could also have shared the nonce (see Trust Chain and Audit Limits).
- The client rebuilds the root and its counts from the vote and those nodes, and checks that they match the published root and tally.
  - It works out which nodes a tree of that size has on the path itself, and rejects a proof with any others.
  - It also rejects a node whose counts don't total the votes under it. Otherwise a server could give one part of the tree an extra vote and another one fewer, and only the voters whose own counts changed would notice.
- If the vote isn't in the tree, the response instead has the leaves just before and after where its nonce would be (just one at either end of the tree, and none in an election with no votes), with the nodes needed to rebuild the root from them. They're next to each other, so they show that no vote lies between them, and so that the voter's validly signed vote isn't counted. That doesn't show the vote was cast, since casting has no receipt (see Trust Chain and Audit Limits).
- Once the results are published, an honest server has a proof for every nonce, and refusing one is how a server could hide a vote it left out. So if the client doesn't get a proof, it warns the voter rather than showing a server error. The voter can try again later and report it with their nonce, or check their vote against every published vote instead, which downloads all of them and checks that they rebuild the published root.
- Auditors also check that the leaves are in nonce order, since proving a vote was left out depends on it.
- A later iteration of the design could have the client ask for the proof of a group of votes instead, like every vote whose nonce starts with the same first few bits as its own, so the server can't tell which is the voter's. The server would send the largest nodes with none of the group's votes under them, and the client would rebuild the rest. With votes published in batches (see Publishing Votes), the group should be the voter's whole batch.

For example, in an election with 16 votes where the client's vote is at position 5, the response has the nodes (4,1), (6,2), (0,4) and (8,8), written as (first_leaf, leaf_count):

```
(0,16)
├── (0,8)
│   ├── (0,4)            ← sent
│   └── (4,4)
│       ├── (4,2)
│       │   ├── (4,1)    ← sent
│       │   └── (5,1)    the client's vote
│       └── (6,2)        ← sent
└── (8,8)                ← sent
```

The client rebuilds (4,2) from (4,1) and its vote, then (4,4) from (4,2) and (6,2), (0,8) from (0,4) and (4,4), and the root from (0,8) and (8,8).

# Mitigating Rigging of Elections By Controlling Parties

Whoever runs an election's server could have it "malfunction" for votes for candidates they oppose, and pass that off as server trouble.
To guard against this, an instance can receive votes for elections hosted elsewhere, through external ballot boxes (see External Ballot Boxes). For example, Party A's server could host its primaries and also receive votes for its candidates in the general election. Each box can be run by people who want its votes counted, and anyone can fetch the votes from every box to tally the election. Once the election closes, the host fetches the votes from every box and publishes them with its own, so everything after that works as if there were no boxes.

Ballot boxes don't settle a voter's claim that a box dropped their vote, which receipts would (see Trust Chain and Audit Limits). If receipts are added, each box would sign them with a key of its own, named in its signed record, so no server would need another's private key.

Boxes also mean the host doesn't see votes arrive, so unless a box shares its logs with the host, neither can link a vote to its voter's account (see Anonymity Limits). This only works if every vote goes to a box, with a catch-all box for the rest, since otherwise the host can see whose votes never reach it. Once the election closes and its blind-signature requests are published, though, a box can match their timestamps to when its votes arrived. A later iteration of the design could have clients wait a random while before casting.

# Request Authentication for API

Any request that needs to be authorized carries a timestamp, the user's public key, the role and jurisdiction it acts under, and a signature. How the MVP sends them is in Signed Requests in the [MVP doc](mvp.md).

- The timestamp is in milliseconds since the epoch, written in decimal without a sign or leading zeros, and must be within a few seconds of the API's clock.
- The public key is the user's public key. It must be an ECDSA P-384 key, and registration rejects any other kind, since browsers check stored requests' signatures with P-384.
- The role and jurisdiction are those of the certificate that authorizes the request. A key has at most one active certificate for each role and jurisdiction, so together they name it. The jurisdiction is a canonical UUID, and is empty for roles without one, like global admin. Both are empty for requests that only need the user's account, like reading their own vote recovery record.
  - Many requests can be made under more than one certificate, like voter authorization by any registrar or admin over the voter's jurisdiction (see Roles), so the client chooses which one to sign under.
- The signature is ECDSA (P-384) with SHA-256, as `r` and `s` concatenated (48 bytes each, so exactly 96 bytes), in base64. It covers these fields, one per line, in this order:
  1. the action, which names what the request does (see below), so a signature means the same thing whatever the endpoint's URL or HTTP method
  2. the instance: the base64 SHA-256 hash of the DER encoding of the root certificate's public key, so a request signed for one instance can't be used on another
  3. the role
  4. the jurisdiction
  5. the timestamp
  6. the body, exactly as sent

  Only the body can contain a newline, so it goes last and no field needs a length prefix.
- The action and instance aren't sent: the API fills in its own when it checks the signature, so a request signed for another action or instance fails.
- The URL isn't signed, so a request's body includes the IDs it acts on, like `election_id` in a request for a blind signature, and the API rejects a body whose IDs don't match the URL. Reads have empty bodies, so which record they read isn't signed. That's fine, since they aren't stored and only need to show who's asking.
- A body is JSON in one canonical encoding, and the API rejects any other encoding. JSON parsers don't all read other encodings the same way, like duplicate keys, unknown fields or field names in a different case, so without this a body could mean one thing to the API and another to an auditor (see Auditing the System).
- There's no nonce. Requests that change something can be repeated safely (clients generate IDs, records are written once, and signing and casting can be repeated), and the timestamp limits how long a request can be replayed.

| Action | What it does | Who can sign it (see Roles) |
| ------ | ------------ | --------------------------- |
| `account.search` | Searches accounts by username, to find one to authorize | any registrar or admin |
| `certificate.list_own` | Lists the signer's own certificates | any account |
| `anchor_pin.update` | Replaces the signer's pin of the instance's anchor (see Pinning the Anchor) | any account |
| `jurisdiction.create` | Creates a jurisdiction | a global admin, or for a sub-jurisdiction, an admin over its parent |
| `voter.authorize` | Authorizes an account's key as a voter in a jurisdiction | a registrar or admin over the jurisdiction |
| `voter.list` | Lists a jurisdiction's voters, with their accounts | a registrar or admin over the jurisdiction |
| `election_key.create` | Creates the key for a new election | an admin over the election's jurisdiction |
| `election.create` | Creates an election, with its candidates and key | an admin over the election's jurisdiction |
| `recovery_record.create` | Uploads the signer's vote recovery record for an election | a voter who can vote in the election |
| `recovery_record.read` | Reads the signer's own recovery record | any account |
| `blind_signature.request` | Requests the blind signature for the signer's vote | a voter who can vote in the election |
| `results.publish` | Publishes an election's results (see Publishing the Root) | an admin over the election's jurisdiction |

Actions for what the MVP doesn't have yet, like deauthorizing voters or changing an election, follow Roles the same way.

# Trust Chain for Everything

The API holds a root key that signs every certificate, starting with the first global admin's (see System Setup).
Jurisdiction creation and changes are signed by whoever made them.
Every other certificate is authorized by a signed request from someone allowed to grant it (see Roles): a voter's by a registrar or admin over the voter's jurisdiction, a registrar's or jurisdiction admin's by an admin over the jurisdiction, and a global admin's by another global admin.
The root's signature alone doesn't make a certificate count, since the API's host holds the root key. A certificate counts only if the request that authorized it was signed under a certificate that counts, and so on up to the first global admin's, whose key is pinned (see Pinning the Anchor).

Authorizations are in the form of x.509 certificates.
A certificate's subject is a single common name for its role and jurisdiction: `system` for the root, `admin.global` for a global admin, and `<role>.<jurisdiction id>.jurisdiction` for the rest, where the role is `admin`, `registrar` or `voter`.
Each role has a separate certificate, so individual roles can be revoked from keys.

Deauthorizations are in the form of a CRL with one entry. Each comes with the signed request that deauthorized the key, from someone allowed to deauthorize it (see Roles), so it traces back to the anchor the same way an authorization does.

## Pinning the Anchor

The anchor is the first global admin's key (see System Setup), the one key with a certificate that no request authorizes. Browsers pin it for each instance, and only trust a certificate whose chain of authorizing requests leads back to it (see Auditing the System). So the API's host can't make a key of its own an admin, or a voter, by issuing it a certificate with the root key, since no chain leads from the anchor to it.

- Only the anchor is pinned. Every other admin's certificate is checked by following its chain to the anchor, so users don't have to pin again when admins change.
- The pin is a SHA-256 hash of the anchor's public key, which is what its fingerprint shows.
- The API serves the anchor's certificate along with the root's, so a browser without a pin still checks that every chain ends at the same key.
- An account pins the anchor when it registers, so nobody else can register until the first global admin has. The sign-up page shows the anchor's fingerprint for the user to compare with the one the instance's operator publishes outside the system, like on a separate website, and registration stores the pin with the account's keys. The first global admin's browser pins their own key.
- The account's pin is encrypted with the account's AES key, with associated data naming it as the pin. So the server can't read or change it, or put another of the account's ciphertexts, like a recovery record, in its place. It's returned with the account's encrypted keys at login, so it follows the user to every device they log in on. Every account has a pin, so a login without one means the server withheld it, and the browser stops.
- Browsers also keep the pin themselves, by the API's origin, so visitors who aren't logged in can check against it too. A visitor without one sees the anchor's fingerprint with a warning that it isn't pinned, and can pin it in the browser. On login, a browser without a pin keeps the account's, and one whose pin differs from the account's stops, since one of them isn't the instance's anchor. Pins are kept by origin rather than by instance, so an API that switches to a new root can't get browsers to treat it as a new instance with nothing pinned yet.
- A chain that ends at any other key fails, and the browser says the anchor doesn't match its pin rather than offering to pin the new one. A user only changes their pin from the Account page (`anchor_pin.update`), after comparing the new fingerprint.
- The pin doesn't change when the first global admin replaces their key. The new key's certificate is authorized by the old key, or by another global admin, and the requests the old key signed still verify, so every chain still leads back to it.

## Auditing the System
Every authorization and every change to a jurisdiction or election is stored as the signed request that made it, so anyone can check each one's chain back to the anchor.
The chain extends to votes: each blind signature is stored with the voter's signed request for it, so an auditor can check that the valid votes in an election don't outnumber requests from distinct authorized voters.

Browsers check a stored request against the root certificate the API serves (see Request Authentication for API). The request must:
- have a signature that verifies under the key stored with it, over the signed data (see Request Authentication for API)
- be signed for the root's instance
- come with a certificate that the root issued to that key, with the common name the API gives the role and jurisdiction the request names
- be signed for the action the record needs, acting under the role and jurisdiction that action needs, with a body naming what the record holds. Bodies are parsed strictly and compared field by field. The API only accepts bodies in their canonical encoding (see Request Authentication for API), so it reads each one the same way browsers do.

The certificate a request was signed under is checked the same way against the request that authorized it, and so on up to the first global admin's certificate, which no request authorizes. Its key must be the pinned anchor (see Pinning the Anchor), so a certificate the root issued with no authorizing request ends its chain at a key that isn't pinned, and fails.
- Each request in the chain must be from someone allowed to make it (see Roles), signed before their certificate was revoked.
- Who's allowed depends on where the jurisdiction a request acts on sat in the tree when the request was signed. So the requests that created that jurisdiction and each one above it, and any that moved them before then, are checked the same way (see Jurisdiction History).
- Browsers check each certificate's chain once per page, so an audit doesn't fetch the chain again for every voter an admin authorized.

The API refuses anything a client sends that browsers would reject when they check it later: account keys that aren't P-384, signatures that aren't exactly 96 bytes, and bodies that aren't in their canonical encoding. Otherwise a single voter could store a request that makes every audit of the election fail, or their own browser report that the server altered their recovery record. Casting already checks votes the way auditors do (see Vote Format).

### What Browsers Check

Each of these follows the chains of the requests it checks, as above:
- An election's page always checks the request that created the election: that an admin over the election's jurisdiction signed it, with the election's details, candidates and key. It shows the fingerprints of the admin's key and the root's. Voting, checking a vote and publishing results also check the request before using the election's key, and stop if it doesn't check out, so voters don't have to compare the key's fingerprint.
- Once the election closes, a button on its page audits every vote and blind-signature request. It downloads all of them, so it only runs when asked. It checks:
  1. every published vote: each is a valid vote in the election, with a valid signature (see Vote Format), and they're in nonce order
  2. the published results, if there are any: that an admin over the election's jurisdiction signed them (see Publishing the Root), and that their vote count, tally and hash tree root match the votes
  3. every blind-signature request: that a voter signed it for this election, under a voter certificate for the election's jurisdiction or one under it, and that it comes with the request authorizing that voter's key, from a registrar or admin over the voter's jurisdiction. It lists the keys that authorized the voters of the requests counted in 4, by fingerprint, with how many voters each authorized, and marks the key that created the election.
  4. that the valid votes don't outnumber requests from distinct authorized voters. Each voter's key and each blinded message counts once. Requests that name a key other than the election's aren't counted. Their voters signed them, so they show the server gave those voters a different key.

  A record that doesn't check out stops the audit, which says which one. Otherwise it lists what it found, including results that don't match the votes, requests that name another key, and more votes than requests.
- A jurisdiction's page has an Audit button, which checks the request that created the jurisdiction: that a global admin, or an admin over its parent, signed it, with the jurisdiction's name and information. It can also count the jurisdiction's voters. That downloads every voter authorization, checks that a registrar or admin over each voter's jurisdiction authorized the voter's key and that the root issued each voter's certificate, and counts the keys, failing if one is listed twice. It also lists the keys that authorized them, by fingerprint, with how many voters each authorized, and marks the key that created the jurisdiction, so counting checks the request that created it first.
- A voter's details, shown to registrars and admins over the voter's jurisdiction, check the voter's authorization, and that it's for the key on the voter's account.

# Known Limits

These are limits of the design itself. The MVP has a few more of its own (see Known Limits in the [MVP doc](mvp.md)).

## Anonymity Limits

- Casting a vote and asking for its proof from the hash tree (see Hashes) aren't authenticated, but the server can link each to the voter's account through the authenticated request just before it, for the blind signature or for the recovery record, which comes from the same IP address, usually over the same connection. So the server can learn which vote is the voter's, when it's cast and again when it's checked.
  - Mitigation for casting: sending every vote to external ballot boxes, though a box can match its votes to voters by time once the election closes. Possible mitigation for that, in a later iteration of the design: clients waiting a random while before casting (see Mitigating Rigging of Elections By Controlling Parties).
  - Possible mitigation for checking, in a later iteration of the design: asking for the proof of a group of votes instead (see Checking a Vote).
- An external ballot box for a candidate only receives that candidate's votes, so where a vote is sent shows how it was cast, both to the box, which sees each voter's IP address, and to anyone watching the voter's network traffic, like their ISP.
- A voter can prove how they voted, because their recovery record ties their signed blind-signature request to their published vote. The "can't prove your vote" goal isn't met.
- Once an election closes, its published blind-signature requests show which voters' keys asked to vote, and when. A voter uses the same key in every election, so anyone who can tie a key to a person can see which elections they voted in, though not how. Registrars and admins over a voter's jurisdiction can see which account has their key, and whoever authorized a voter saw their fingerprint.

## Auditability Limits

- Votes can't be checked or audited until the election closes, since that's when they're published (see Publishing Votes). So a voter can't check that their vote is there, and nobody can catch a server dropping or adding votes, until the election is over.
  - Possible mitigation for a later iteration of the design: publishing votes in batches during the election (see Publishing Votes).
- Nobody can see the results until the election closes, only how many votes have been cast, and with external ballot boxes, not even that (see Publishing Votes).

## Authentication Limits

- The API's host can still run an offline dictionary attack on any account (RFC 9807 §10.11), since it holds the seed and the records. Each guess costs an Argon2id run for each account, so accounts are only as safe as their passwords. An account's signing key and AES key are stored on the server encrypted under its password, so a server that gets them, by cracking the password or from the user, can act as that user anywhere:
  - It can sign anything the user's certificates allow, and the requests check out like the user's own. For a voter who didn't vote, it can request a blind signature and add a vote that the check against requests can't catch (see Auditing the System). For an admin, it can sign voter authorizations, results, or an election with a key of its own for some voters, so it can recognize their votes, though the election's audit shows that key once it closes (see Casting a Vote). The anchor can authorize anyone, so the first global admin's password matters most.
  - It can decrypt the user's recovery records, which show how they voted.
  - Deauthorizing or replacing the key doesn't stop it. A request's timestamp is whatever its signer chose, and the API only checks it against its own clock when the request arrives, so browsers can't tell a request the server dated before the deauthorization from a real one.
- The seed and the server's key pair can't be replaced without every account registering again.

## Trust Chain and Audit Limits

- Browsers' checks are only as trustworthy as the frontend code that runs them. Whoever serves that code could serve a version that skips the checks, or that sends itself users' passwords and keys. So the frontend has to come from a host its users trust, separate from the hosts that run elections' APIs, which it calls across origins.
- Pinning only protects users who compare the anchor's fingerprint with the one the operator publishes. Whoever pins without comparing trusts the API at that moment, and a visitor who never pins only sees fingerprints. Either way, the API's host could use the root key to give them an anchor of its own, and sign anything with it (see Pinning the Anchor).
- The server could withhold records, or show different people different ones, since nothing like a transparency log fixes what's published. The audit only checks the records it's given.
- The check bounds how many votes there are, not which votes they are. The server holds the election's private key, so it can sign a vote of its own for any voter who got a blind signature but didn't cast a vote, or in place of a vote it dropped, and the count still fits the requests. A voter who checks their own vote would find it missing, but nobody can notice a vote added for a voter who never cast one. Closing this needs an election key the server doesn't hold alone, such as one split among independent parties.
- A validly signed vote that isn't counted doesn't show the server dropped it. Casting has no receipt, so the voter could have held the vote back, or given it the nonce of a vote that was cast first, and the server couldn't show otherwise. Votes are only published once the election closes, so a voter can only learn another vote's nonce from whoever cast it. A possible future improvement is a receipt that the receiving server signs for each vote it accepts, which would settle these disputes (see Mitigating Rigging of Elections By Controlling Parties for how that would work with several receivers).

# Data Model

This describes what each table is for and what the design needs from it. Column-level detail is in [mvp.md](mvp.md), for the tables the MVP has.

## Accounts

Each account stores its pin of the instance's anchor, encrypted with the account's AES key (see Pinning the Anchor).

A later iteration could add a second factor for accounts, like TOTP.

## Certificates

Certificates are used to determine permissions for keys (mostly users' keys).
Certificates generally follow the x.509 standard, and grant the given key one role (see Trust Chain for Everything).

## Voting Jurisdictions

Voting Jurisdictions are intended to be nested geographic areas, so users will be part of all elections for their city, county, district, state, etc.
Each has a name, a description that identifies it (like its location), and the jurisdiction it's under, if any. A jurisdiction can be deactivated, but never deleted, and can have an image (see Files). Changes are recorded in Jurisdiction History.

## Jurisdiction History

Jurisdiction History records each version of a jurisdiction: its fields as they were after one change, with the signed request that made it (see Signed Requests). The first entry is its creation.

## Election

An Election is specific to a Jurisdiction, but is vote-able by all users who belong to sub-jurisdictions as well.
Each has a title, a description, when it opens and closes, and its key. It can also allow write-ins (see Vote Format), be canceled, and have an image (see Files). Changes are recorded in Election History.
A later iteration could identify elections by a SHA-256 hash of their key instead, to keep IDs unique across instances.

An external election, one this instance only receives votes for, has no jurisdiction here, so a global admin creates it. Its key is the host election's, and it may be created from just the host election's URL, with its details fetched from the host. Before creating it, the global admin's browser checks the request that created the host election back to the host's anchor, as an election page does (see What Browsers Check). Otherwise the host could give it a different key, so it would reject every real vote.

## Election History

Election History records each version of an election: its fields as they were after one change, with the signed request that made it (see Signed Requests). The first entry is its creation. An election's key never changes, since the request that created the election certifies it (see Election Keys).

## External Ballot Boxes

External Ballot Boxes are receivers for votes that are running on other instances of this voting system.
A box is recorded on the instance running the actual election, and the instance receiving the votes does so in an external election of its own (see Election).
Each box names its election, the candidate whose votes it receives, and the URL that votes are posted to. A box with no candidate is a catch-all for any votes not covered by other boxes.
A box is created and canceled by signed requests (see Signed Requests), and is never changed: one set up wrong is canceled instead. What boxes are for is in Mitigating Rigging of Elections By Controlling Parties.

## Candidates

Candidates are options to vote for in an election.
Each has a name, a description, an image and its place on the ballot. A candidate taken off the ballot is kept, and marked as removed. Changes are recorded in Candidate History.

## Candidate History

Candidate History records each version of a candidate: its fields as they were after one change, with the signed request that made it (see Signed Requests). The first entry is its creation. A candidate's election never changes.

## Blinded Signed Votes

Blinded Signed Votes are votes that have been signed by the system, each stored with the voter's signed request for the signature.
What the client needs to unblind the signature is kept in Vote Recovery Records, encrypted by the client.

## Vote Recovery Records

Vote Recovery Records hold what a voter's client needs to finish casting or find its vote from any device, encrypted with the user's AES key, each with the signed request that uploaded it (see Casting a Vote).
Uploading a record takes a voter certificate for the election's jurisdiction, but reading your own only takes a request signed by your account, so you can still check past votes after being deauthorized. Reading a record can't be used to vote.
The plaintext format only matters to the client, since the server can't read it.
The user's AES key must never be replaced (a password change re-encrypts the existing key instead), because recovery records can't be rewritten under a new key.

## Votes

Votes represent the votes cast by clients.
The nonce and raw vote are kept to validate the signature.

There is deliberately no timestamp column, since when a vote arrived could link it to the voter's blind-signature request.
The count of votes cast isn't stored with each vote, since that would record the order votes arrived in.

## Signing Keys

Signing Keys are public keys (and potentially private keys) used by various entities in the system.
A key can be deactivated, since an entity shouldn't have many keys at once.

## Signed Requests

Signed Requests store authenticated requests exactly as they were signed (see Request Authentication for API), so their signatures can be checked again later.
They're the signed requests later checks need, like the ones that create jurisdictions and elections, authorize voters, upload vote recovery records, request blind signatures and publish results.

Vote recovery uploads are only returned to their owner, and the rest are published for auditing.

## Properties

Properties are system-wide settings, each a unique name with a value.

## Files

Files hold images for candidates and jurisdictions. Each file's ID is the SHA-256 hash of its data, so a signed request that names an image fixes its content, and browsers can check the image they're shown against it.

## Election Results

Election Results record an election's published tally and the root of its hash tree (see Publishing the Root). A result never changes.
