import { RSABSSA } from "@cloudflare/blindrsa-ts"
import { arrayBufferToBase64, base64ToArrayBuffer } from "./base64"
import { decryptWithAES, encryptWithAES } from "./keys"

// votes are signed with RSABSSA-SHA384-PSS-Randomized (RFC 9474), the variant election keys are
// created for
const suite = RSABSSA.SHA384.PSS.Randomized()

// NONCE_BYTES is the length of the random prefix that RFC 9474's Prepare step adds to a vote, which
// is the vote's nonce
const NONCE_BYTES = 32

// Ballot is everything a client needs to finish casting a vote: the vote's nonce (lowercase hex), the
// vote JSON, the blinded message sent to be signed (base64), and inv (base64), which unblinds the
// signature. A vote recovery record holds one, encrypted.
export interface Ballot {
    nonce: string;
    vote: string;
    blinded_message: string;
    inv: string;
}

// buildVote returns the vote JSON for a candidate in an election, in the one encoding the server
// accepts: these fields in this order, with no whitespace. The ids must be lowercase, which is how the
// server returns them.
export function buildVote(election_id : string, candidate_id : string) : string {
    return JSON.stringify({ version: 1, election_id, candidate_id })
}

// voteCandidate returns the id of the candidate a ballot's vote is for, or null if the vote isn't for
// the election
export function voteCandidate(ballot : Ballot, election_id : string) : string|null {
    let vote
    try {
        vote = JSON.parse(ballot.vote)
    } catch {
        return null
    }
    if (vote == null || vote.election_id !== election_id || typeof vote.candidate_id !== "string") {
        return null
    }

    return vote.candidate_id
}

// CANDIDATE_ID_PATTERN matches a candidate ID in canonical form: a lowercase, hyphenated UUID
const CANDIDATE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// canonicalVoteCandidate returns the ID of the candidate a vote JSON is for, or null unless it's a
// vote in the election in exactly the encoding buildVote produces. That's the check the server makes
// when a vote is cast, so everyone who counts votes counts the same ones.
export function canonicalVoteCandidate(vote_json : string, election_id : string) : string|null {
    let vote
    try {
        vote = JSON.parse(vote_json)
    } catch {
        return null
    }
    if (vote == null || typeof vote.candidate_id !== "string" || !CANDIDATE_ID_PATTERN.test(vote.candidate_id)) {
        return null
    }

    // whitespace, other fields, other field orders, other versions and other elections don't
    // survive the round trip
    if (buildVote(election_id, vote.candidate_id) !== vote_json) {
        return null
    }

    return vote.candidate_id
}

function bytesToHex(bytes : Uint8Array) : string {
    return Array.from(bytes)
        .map(byte => ("0" + byte.toString(16)).slice(-2))
        .join("")
}

function hexToBytes(hex : string) : Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(2 * i, 2 * i + 2), 16)
    }
    return bytes
}

// bytesToBase64 encodes exactly the bytes in view, which may be part of a larger buffer
function bytesToBase64(bytes : Uint8Array) : string {
    return arrayBufferToBase64(bytes.slice().buffer)
}

// voteMessage returns what the election key signs for a vote: its nonce (lowercase hex) followed by
// the vote JSON
function voteMessage(nonce_hex : string, vote_json : string) : Uint8Array {
    const nonce : Uint8Array = hexToBytes(nonce_hex)
    const vote : Uint8Array = new TextEncoder().encode(vote_json)

    const message = new Uint8Array(nonce.length + vote.length)
    message.set(nonce, 0)
    message.set(vote, nonce.length)
    return message
}

// signedMessage returns what the election key signs for a ballot: the nonce followed by the vote
function signedMessage(ballot : Ballot) : Uint8Array {
    return voteMessage(ballot.nonce, ballot.vote)
}

// PSS_SALT_BYTES is the salt length of the signatures RFC 9474 produces for the SHA-384 variants,
// which is the hash's length
const PSS_SALT_BYTES = 48

// verifyVoteSignature reports whether signature (base64) is the election key's (from
// checkElectionKey) over a vote's nonce (lowercase hex) followed by the vote JSON. RFC 9474's
// signatures are RSA-PSS signatures, so standard verification checks them.
export async function verifyVoteSignature(election_key : CryptoKey, nonce : string, vote : string, signature : string) : Promise<boolean> {
    let signature_bytes : ArrayBuffer
    try {
        signature_bytes = base64ToArrayBuffer(signature)
    } catch {
        return false
    }

    return await crypto.subtle.verify({ name: "RSA-PSS", saltLength: PSS_SALT_BYTES }, election_key, signature_bytes, voteMessage(nonce, vote))
}

// prepareBallot adds a random nonce to the vote and blinds it under the election key (from
// checkElectionKey), so the server can sign it without seeing it
export async function prepareBallot(election_key : CryptoKey, vote : string) : Promise<Ballot> {
    const prepared : Uint8Array = suite.prepare(new TextEncoder().encode(vote))
    const { blindedMsg, inv } = await suite.blind(election_key, prepared)

    return {
        nonce: bytesToHex(prepared.slice(0, NONCE_BYTES)),
        vote,
        blinded_message: bytesToBase64(blindedMsg),
        inv: bytesToBase64(inv),
    }
}

// finalizeBallot unblinds the server's blind signature (base64) for the ballot and returns the
// signature, as base64. Unblinding also checks the signature, so this throws unless it is a valid
// signature on the vote.
export async function finalizeBallot(election_key : CryptoKey, ballot : Ballot, blind_signature : string) : Promise<string> {
    const signature : Uint8Array = await suite.finalize(
        election_key,
        signedMessage(ballot),
        new Uint8Array(base64ToArrayBuffer(blind_signature)),
        new Uint8Array(base64ToArrayBuffer(ballot.inv)),
    )

    return bytesToBase64(signature)
}

// encryptBallot encrypts a ballot with the user's AES key, for a vote recovery record
export async function encryptBallot(aes_key : CryptoKey, ballot : Ballot) : Promise<string> {
    const plaintext : Uint8Array = new TextEncoder().encode(JSON.stringify(ballot))
    return bytesToBase64(await encryptWithAES(aes_key, plaintext))
}

// decryptBallot decrypts the ballot in a vote recovery record with the user's AES key. It throws if
// the record can't be decrypted or doesn't hold a ballot.
export async function decryptBallot(aes_key : CryptoKey, encrypted_record : string) : Promise<Ballot> {
    const plaintext : ArrayBuffer = await decryptWithAES(aes_key, new Uint8Array(base64ToArrayBuffer(encrypted_record)))
    const ballot = JSON.parse(new TextDecoder().decode(plaintext))

    for (const field of ["nonce", "vote", "blinded_message", "inv"]) {
        if (typeof ballot[field] !== "string") {
            throw new Error("vote recovery record has no " + field)
        }
    }

    return {
        nonce: ballot.nonce,
        vote: ballot.vote,
        blinded_message: ballot.blinded_message,
        inv: ballot.inv,
    }
}
