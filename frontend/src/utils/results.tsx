import { CertificateRole } from "@/models/certificate";
import { Election } from "@/services/electionservice";
import { getBlindSignatureRequests, getPublishedVotes, getResults, PUBLISH_RESULTS_ACTION, PublishedResults, PublishedVote, TallyEntry, VoteProof } from "@/services/voteservice";
import { auditBlindSignatureRequests, BlindSignatureAudit, checkElectionKey, checkRequest } from "@/utils/audit";
import { canonicalJSON } from "@/utils/auth";
import { canonicalVoteCandidate, verifyVoteSignature } from "@/utils/ballot";
import { buildTree, Counts, countsTotal, decodeCounts, EMPTY_ROOT_HASH, hashBytes, isNonce, rootFromPath, TreeLeaf } from "@/utils/hashtree";
import { getRoot, Root } from "@/utils/root";

// ResultsError is an error with a message to show the user
export class ResultsError extends Error {}

// ResultsBody is what an admin signs to publish an election's results: how many votes it has, the
// root hash of its hash tree (base64), and its tally, which is the root's counts, exactly as hashed
export interface ResultsBody {
    election_id: string;
    vote_count: number;
    root_hash: string;
    tally: string;
}

// encodeResultsBody returns the one encoding of a results body that the API accepts: these fields in
// this order, with no whitespace (see canonicalJSON)
export function encodeResultsBody(body : ResultsBody) : string {
    return canonicalJSON({
        election_id: body.election_id,
        vote_count: body.vote_count,
        root_hash: body.root_hash,
        tally: body.tally,
    })
}

// parseResultsBody parses a results body, which must be exactly what encodeResultsBody produces, with
// a tally that counts every vote. It throws otherwise.
function parseResultsBody(encoded : string) : ResultsBody {
    const parsed = JSON.parse(encoded)
    if (parsed == null || typeof parsed.election_id !== "string" || typeof parsed.vote_count !== "number" || typeof parsed.root_hash !== "string" || typeof parsed.tally !== "string") {
        throw new Error("results body doesn't have the right fields")
    }

    const body : ResultsBody = {
        election_id: parsed.election_id,
        vote_count: parsed.vote_count,
        root_hash: parsed.root_hash,
        tally: parsed.tally,
    }
    // whitespace, other fields, other field orders and repeated fields don't survive the round trip
    if (encodeResultsBody(body) !== encoded) {
        throw new Error("results body isn't in canonical form")
    }

    hashBytes(body.root_hash)
    if (!Number.isSafeInteger(body.vote_count) || body.vote_count < 0 || countsTotal(decodeCounts(body.tally)) !== body.vote_count) {
        throw new Error("results' tally doesn't count every vote")
    }

    return body
}

// VerifiedResults are an election's published results, once the signed request publishing them has
// been checked
export interface VerifiedResults {
    body: ResultsBody;
    tally: Counts;
    // signer_public_key is the PEM public key of the global admin who signed the results
    signer_public_key: string;
    // signed_timestamp is when the results were signed, from the signed request (milliseconds since
    // the epoch). The server only accepts requests signed close to when it gets them.
    signed_timestamp: number;
}

// verifyResults checks the signed request that published an election's results, and returns them.
// It throws unless a global admin signed the request (see checkRequest), to publish results, with a
// valid timestamp and results body for the election.
export async function verifyResults(election : Election, published : PublishedResults, root : Root) : Promise<VerifiedResults> {
    const signed_request = published.signed_request
    await checkRequest(signed_request, root, PUBLISH_RESULTS_ACTION, CertificateRole.global_admin, null)

    const body : ResultsBody = parseResultsBody(signed_request.body)
    if (body.election_id !== election.id) {
        throw new Error("results are for a different election")
    }

    // the server parses the timestamp as an integer number of milliseconds
    const signed_timestamp = Number(signed_request.request_timestamp)
    if (!Number.isSafeInteger(signed_timestamp)) {
        throw new Error("results' request timestamp isn't a number of milliseconds")
    }

    return {
        body,
        tally: decodeCounts(body.tally),
        signer_public_key: signed_request.public_key,
        signed_timestamp,
    }
}

// tallyEntries lists a tally's counts for the election's candidates in ballot order, including those
// with no votes, then the counts for any other candidate IDs that votes named, in ID order, like the
// API's vote summary
export function tallyEntries(election : Election, tally : Counts) : TallyEntry[] {
    const entries : TallyEntry[] = election.candidates.map(candidate => ({
        candidate_id: candidate.id,
        votes: tally.get(candidate.id) ?? 0,
    }))

    const others : string[] = Array.from(tally.keys())
        .filter(candidate_id => !election.candidates.some(candidate => candidate.id == candidate_id))
        .sort()
    for (const candidate_id of others) {
        entries.push({ candidate_id, votes: tally.get(candidate_id) ?? 0 })
    }

    return entries
}

// auditVotes checks every published vote in an election the way an auditor would, then rebuilds the
// election's hash tree from them and returns the results an admin would sign. election_key is from
// checkElectionKey. It throws a ResultsError naming the first vote that isn't valid, or that's
// out of nonce order: proving a vote was left out of the tree depends on that order.
export async function auditVotes(election : Election, election_key : CryptoKey, votes : PublishedVote[]) : Promise<ResultsBody> {
    const leaves : TreeLeaf[] = []
    for (let i = 0; i < votes.length; i++) {
        const vote : PublishedVote = votes[i]

        if (!isNonce(vote.nonce)) {
            throw new ResultsError("Published vote " + (i + 1) + " doesn't have a valid nonce.")
        }
        // lowercase hex compares in the same order as the bytes it encodes
        if (i > 0 && !(votes[i - 1].nonce < vote.nonce)) {
            throw new ResultsError("The published votes aren't in nonce order, at the vote with nonce " + vote.nonce + ".")
        }

        const candidate_id : string|null = canonicalVoteCandidate(vote.vote, election.id)
        if (candidate_id == null) {
            throw new ResultsError("The published vote with nonce " + vote.nonce + " isn't a valid vote in this election.")
        }
        if (!await verifyVoteSignature(election_key, vote.nonce, vote.vote, vote.signature)) {
            throw new ResultsError("The published vote with nonce " + vote.nonce + " doesn't have a valid signature.")
        }

        leaves.push({ nonce: vote.nonce, signature: vote.signature, vote: vote.vote, candidate_id })
    }

    const { root } = await buildTree(leaves)

    return {
        election_id: election.id,
        vote_count: leaves.length,
        root_hash: root.hash,
        tally: root.counts,
    }
}

// auditPublishedVotes downloads every published vote in an election, then checks them and rebuilds
// its hash tree with auditVotes, once the election's key checks out (see checkElectionKey). onStep
// reports progress.
export async function auditPublishedVotes(election : Election, onStep : (step : string) => void) : Promise<ResultsBody> {
    onStep("Checking the election key")
    let election_key : CryptoKey
    try {
        election_key = await checkElectionKey(election, await getRoot())
    } catch (error) {
        console.log("election key check failed", error)
        throw new ResultsError("The election's key couldn't be confirmed, so its votes can't be checked.")
    }

    onStep("Downloading the published votes")
    const resp = await getPublishedVotes(election.id)
    if (resp == null) {
        throw new ResultsError("Error connecting to server to fetch the published votes")
    }
    if (resp.status_code == 404) {
        throw new ResultsError("The votes aren't published yet.")
    }
    if (resp.status_code != 200) {
        throw new ResultsError("Unknown server error (status " + resp.status_code + ")")
    }

    onStep("Checking " + resp.votes.length.toLocaleString() + " votes and rebuilding the hash tree")
    return await auditVotes(election, election_key, resp.votes)
}

// AuditedElection is what auditElection found in an election's published records, once each one has
// been checked
export interface AuditedElection {
    // votes are the results the published votes give (see auditVotes)
    votes: ResultsBody;
    // results are the published results, once their signature has been checked (see verifyResults),
    // or null if they haven't been published
    results: VerifiedResults | null;
    // request_count is how many requests for blind signatures were published
    request_count: number;
    // requests is what they count toward (see auditBlindSignatureRequests)
    requests: BlindSignatureAudit;
}

// auditElection downloads every published vote and request for a blind signature in an election, and
// the published results, and checks each one (see auditPublishedVotes, verifyResults and
// auditBlindSignatureRequests). Comparing what they add up to is left to the caller. onStep reports
// progress. It throws a ResultsError saying what didn't check out, or couldn't be fetched.
export async function auditElection(election : Election, onStep : (step : string) => void) : Promise<AuditedElection> {
    const votes : ResultsBody = await auditPublishedVotes(election, onStep)
    // auditPublishedVotes already loaded the root, to check the election's key
    const root : Root = await getRoot()

    onStep("Checking the published results")
    const results_resp = await getResults(election.id)
    if (results_resp == null) {
        throw new ResultsError("Error connecting to server to fetch the published results")
    }
    let results : VerifiedResults|null = null
    if (results_resp.status_code == 200 && results_resp.results != null) {
        try {
            results = await verifyResults(election, results_resp.results, root)
        } catch (error) {
            throw new ResultsError("The published results don't check out (" + errorMessage(error) + ").")
        }
    } else if (results_resp.status_code != 404) {
        throw new ResultsError("Unknown server error (status " + results_resp.status_code + ")")
    }

    onStep("Downloading the requests for blind signatures")
    const requests_resp = await getBlindSignatureRequests(election.id)
    if (requests_resp == null) {
        throw new ResultsError("Error connecting to server to fetch the requests for blind signatures")
    }
    if (requests_resp.status_code == 404) {
        throw new ResultsError("The requests for blind signatures aren't published yet.")
    }
    if (requests_resp.status_code != 200) {
        throw new ResultsError("Unknown server error (status " + requests_resp.status_code + ")")
    }

    onStep("Checking " + requests_resp.requests.length.toLocaleString() + " requests for blind signatures")
    let requests : BlindSignatureAudit
    try {
        requests = await auditBlindSignatureRequests(election, requests_resp.requests, root)
    } catch (error) {
        throw new ResultsError("The requests for blind signatures don't check out (" + errorMessage(error) + ").")
    }

    return { votes, results, request_count: requests_resp.requests.length, requests }
}

// errorMessage returns the message of an error from a check, to show the user what didn't check out
function errorMessage(error : unknown) : string {
    return error instanceof Error ? error.message : String(error)
}

// ProofResult is what a proof shows about a vote: that it's counted in the published results, that
// a different vote (or one without a valid signature) was published with its nonce, or that it was
// left out
export type ProofResult = "counted" | "replaced" | "left_out"

// checkProof checks the API's proof for a vote's nonce against an election's published results, and
// returns what it shows. vote is the voter's own vote JSON, and election_key is from
// checkElectionKey. It throws if the proof doesn't show one of those, which means the server's
// proof doesn't match the results it published.
export async function checkProof(election : Election, election_key : CryptoKey, results : ResultsBody, nonce : string, vote : string, proof : VoteProof) : Promise<ProofResult> {
    // nonces are compared as strings below, which only matches their bytes' order in lowercase hex
    if (!isNonce(nonce)) {
        throw new Error("vote's nonce isn't 32 bytes of lowercase hex")
    }

    const size : number = results.vote_count
    const leaves = proof.leaves

    // every leaf has to rebuild the published root, so the proof is about the same tree everyone
    // else checks against
    const signed : boolean[] = []
    for (const leaf of leaves) {
        const candidate_id : string|null = canonicalVoteCandidate(leaf.vote, election.id)
        if (candidate_id == null) {
            throw new Error("proof has a vote that isn't valid in the election")
        }

        const root = await rootFromPath({ nonce: leaf.nonce, signature: leaf.signature, vote: leaf.vote, candidate_id }, leaf.position, size, leaf.path)
        if (root.hash !== results.root_hash || root.counts !== results.tally) {
            throw new Error("proof doesn't rebuild the published root")
        }

        signed.push(await verifyVoteSignature(election_key, leaf.nonce, leaf.vote, leaf.signature))
    }

    if (leaves.some(leaf => leaf.nonce === nonce)) {
        if (leaves.length != 1) {
            throw new Error("proof has more than the vote with the nonce")
        }

        return leaves[0].vote === vote && signed[0] ? "counted" : "replaced"
    }

    // otherwise the proof has the votes on either side of where the vote would be, which are next
    // to each other in the tree, or at one of its ends, so there's no vote between them
    if (!signed.every(valid => valid)) {
        throw new Error("proof has a vote without a valid signature")
    }
    if (leaves.length == 0 && size == 0 && results.root_hash === EMPTY_ROOT_HASH) {
        return "left_out"
    }
    if (leaves.length == 1) {
        const [leaf] = leaves
        if ((leaf.position == 0 && nonce < leaf.nonce) || (leaf.position == size - 1 && leaf.nonce < nonce)) {
            return "left_out"
        }
    }
    if (leaves.length == 2) {
        const [before, after] = leaves
        if (before.position + 1 == after.position && before.nonce < nonce && nonce < after.nonce) {
            return "left_out"
        }
    }

    throw new Error("proof doesn't show where the vote would be")
}
