import { CertificateRole } from "@/models/certificate"
import { canonicalJSON, getConfigForAuthenticatedRequest, SignedRequest } from "@/utils/auth"
import { TreeNode } from "@/utils/hashtree"
import axios from "axios"

export class GetRecoveryRecordResponse {
    status_code: number = 200;
    // the request that uploaded the record, whose body holds the encrypted record
    signed_request: SignedRequest|null = null;
}

export class CreateRecoveryRecordResponse {
    status_code: number = 201;
    // the request that uploaded the record, whose body holds the encrypted record
    signed_request: SignedRequest|null = null;
}

export class BlindSignatureResponse {
    status_code: number = 201;
    // base64
    blind_signature: string = "";
}

// BlindSignatureRequest is a voter's published request for a blind signature, with the admin's
// signed request that authorized the voter (see auditBlindSignatureRequests)
export interface BlindSignatureRequest {
    signed_request: SignedRequest;
    authorization: SignedRequest;
}

export class GetBlindSignatureRequestsResponse {
    status_code: number = 200;
    // in the order they were signed
    requests: BlindSignatureRequest[] = [];
}

export class CastVoteResponse {
    status_code: number = 201;
}

// CREATE_RECOVERY_RECORD_ACTION is the action of the signed request that uploads a voter's recovery
// record, which holds the record in its body
export const CREATE_RECOVERY_RECORD_ACTION = "recovery_record.create"

// REQUEST_BLIND_SIGNATURE_ACTION is the action of the signed request that asks for a blind signature
// on a voter's blinded vote
export const REQUEST_BLIND_SIGNATURE_ACTION = "blind_signature.request"

// recoveryRecordEndpoint is where the voter's recovery record for the election is uploaded and read
function recoveryRecordEndpoint(election_id : string) : string {
    return "/api/v1/elections/" + encodeURIComponent(election_id) + "/recovery-record"
}

// getRecoveryRecord fetches the user's recovery record for the election, which is a 404 if they
// haven't started voting in it. It only needs their account, not a current voter certificate.
export async function getRecoveryRecord(election_id : string) : Promise<GetRecoveryRecordResponse|null> {
    const endpoint = recoveryRecordEndpoint(election_id)

    const request_config = await getConfigForAuthenticatedRequest("recovery_record.read", null, null, "")
    if (request_config === null) {
        return null;
    }

    const resp : GetRecoveryRecordResponse = new GetRecoveryRecordResponse()
    try {
        const response = await axios.get<SignedRequest>(endpoint, request_config)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.signed_request = response.data
        }
    } catch (error) {
        console.log("recovery record get error", error)
        return null;
    }

    return resp;
}

// createRecoveryRecord uploads the user's recovery record for the election (base64, encrypted with
// their AES key), as a voter in voter_jurisdiction_id. Records can't be replaced: uploading a
// different one is a 409, but sending exactly the same body again is a 200.
export async function createRecoveryRecord(election_id : string, voter_jurisdiction_id : string, encrypted_record : string) : Promise<CreateRecoveryRecordResponse|null> {
    // the election is in the URL too, but the URL isn't signed, so the signed request needs it to say
    // which election the record is for
    const body = canonicalJSON({ election_id, encrypted_record })
    const endpoint = recoveryRecordEndpoint(election_id)

    const request_config = await getConfigForAuthenticatedRequest(CREATE_RECOVERY_RECORD_ACTION, CertificateRole.voter, voter_jurisdiction_id, body)
    if (request_config === null) {
        return null;
    }

    const resp : CreateRecoveryRecordResponse = new CreateRecoveryRecordResponse()
    try {
        const response = await axios.post<SignedRequest>(endpoint, body, request_config)
        resp.status_code = response.status
        if (response.status == 200 || response.status == 201) {
            resp.signed_request = response.data
        }
    } catch (error) {
        console.log("recovery record post error", error)
        return null;
    }

    return resp;
}

// requestBlindSignature asks for the election key's signature on the user's blinded vote (base64), as
// a voter in voter_jurisdiction_id. public_key_hash names the key the vote was blinded under (see
// publicKeyHash), so the signed request records it. Asking again with the same blinded message
// returns the same signature (200); a different one is a 409.
export async function requestBlindSignature(election_id : string, voter_jurisdiction_id : string, blinded_message : string, public_key_hash : string) : Promise<BlindSignatureResponse|null> {
    // the election is in the URL too, but the URL isn't signed, so the signed request needs it to say
    // which election the vote is for
    const body = canonicalJSON({ election_id, blinded_message, public_key_hash })
    const endpoint = "/api/v1/elections/" + encodeURIComponent(election_id) + "/blind-signatures"

    const request_config = await getConfigForAuthenticatedRequest(REQUEST_BLIND_SIGNATURE_ACTION, CertificateRole.voter, voter_jurisdiction_id, body)
    if (request_config === null) {
        return null;
    }

    const resp : BlindSignatureResponse = new BlindSignatureResponse()
    try {
        const response = await axios.post<{ blind_signature: string }>(endpoint, body, request_config)
        resp.status_code = response.status
        if (response.status == 200 || response.status == 201) {
            resp.blind_signature = response.data.blind_signature
        }
    } catch (error) {
        console.log("blind signature post error", error)
        return null;
    }

    return resp;
}

// getBlindSignatureRequests fetches every voter's published request for a blind signature in the
// election, which is a 404 until the election's votes are published. Every voter who had a vote
// signed has one, so it can be large.
export async function getBlindSignatureRequests(election_id : string) : Promise<GetBlindSignatureRequestsResponse|null> {
    const endpoint = "/api/v1/elections/" + encodeURIComponent(election_id) + "/blind-signature-requests"

    const resp : GetBlindSignatureRequestsResponse = new GetBlindSignatureRequestsResponse()
    try {
        const response = await axios.get<BlindSignatureRequest[]>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.requests = response.data
        }
    } catch (error) {
        console.log("blind signature requests get error", error)
        return null;
    }

    return resp;
}

// castVote casts a vote: its nonce (lowercase hex), the vote JSON, and the election key's signature
// over them (base64). Casting the same vote again is a 200.
export async function castVote(election_id : string, nonce : string, vote : string, signature : string) : Promise<CastVoteResponse|null> {
    const body = JSON.stringify({ nonce, vote, signature })
    const endpoint = "/api/v1/elections/" + encodeURIComponent(election_id) + "/votes"

    const resp : CastVoteResponse = new CastVoteResponse()
    try {
        // not authenticated, so the vote isn't directly tied to the user's account, but the server
        // can link the two through the authenticated requests around it, like the one for the blind
        // signature
        const response = await axios.post(endpoint, body)
        resp.status_code = response.status
    } catch (error) {
        console.log("vote post error", error)
        return null;
    }

    return resp;
}

// TallyEntry is how many of the published votes are for a candidate
export interface TallyEntry {
    candidate_id: string;
    votes: number;
}

// VoteSummary summarizes the votes in an election. Votes are only published once the election closes,
// and complete is true from then on. The tally is empty until then.
export interface VoteSummary {
    votes_cast: number;
    complete: boolean;
    // the votes for each candidate on the ballot, in ballot order, then for any other candidate IDs
    // that votes named
    tally: TallyEntry[];
}

export class GetVoteSummaryResponse {
    status_code: number = 200;
    summary: VoteSummary|null = null;
}

// PublishedVote is a published vote: its nonce (lowercase hex), the vote JSON exactly as signed, and
// the election key's signature (base64)
export interface PublishedVote {
    nonce: string;
    vote: string;
    signature: string;
}

export class GetPublishedVotesResponse {
    status_code: number = 200;
    // in nonce order
    votes: PublishedVote[] = [];
}

// publishedVotesEndpoint is where an election's votes are downloaded once it has closed, as one JSON
// object per line. What it serves never changes once it's published.
export function publishedVotesEndpoint(election_id : string) : string {
    return "/api/v1/elections/" + encodeURIComponent(election_id) + "/votes/published"
}

// getVoteSummary fetches the summary of the votes in an election
export async function getVoteSummary(election_id : string) : Promise<GetVoteSummaryResponse|null> {
    const endpoint = "/api/v1/elections/" + encodeURIComponent(election_id) + "/votes/summary"

    const resp : GetVoteSummaryResponse = new GetVoteSummaryResponse()
    try {
        const response = await axios.get<VoteSummary>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.summary = response.data
        }
    } catch (error) {
        console.log("vote summary get error", error)
        return null;
    }

    return resp;
}

// getPublishedVotes downloads every vote in an election, which is a 404 until the election closes.
// Everyone downloads the same file, so it tells the server nothing about which vote is the user's.
export async function getPublishedVotes(election_id : string) : Promise<GetPublishedVotesResponse|null> {
    const resp : GetPublishedVotesResponse = new GetPublishedVotesResponse()
    try {
        // fetched as text, since it's one JSON object per line rather than one JSON document
        const response = await axios.get<string>(publishedVotesEndpoint(election_id), { responseType: "text" })
        resp.status_code = response.status
        if (response.status == 200) {
            resp.votes = response.data.split("\n")
                .filter(line => line != "")
                .map(line => JSON.parse(line) as PublishedVote)
        }
    } catch (error) {
        console.log("published votes get error", error)
        return null;
    }

    return resp;
}

// PUBLISH_RESULTS_ACTION is the action of the signed request that publishes an election's results
export const PUBLISH_RESULTS_ACTION = "results.publish"

// resultsEndpoint is where an election's results are published and read
function resultsEndpoint(election_id : string) : string {
    return "/api/v1/elections/" + encodeURIComponent(election_id) + "/results"
}

// PublishedResults are an election's published results: the admin's signed request publishing them,
// which has to be checked before they're trusted, and when the server stored them (a Unix timestamp),
// which isn't signed
export interface PublishedResults {
    signed_request: SignedRequest;
    created_timestamp: number;
}

export class GetResultsResponse {
    status_code: number = 200;
    results: PublishedResults|null = null;
}

export class PublishResultsResponse {
    status_code: number = 201;
}

// getResults fetches an election's published results, which is a 404 until an admin publishes them
export async function getResults(election_id : string) : Promise<GetResultsResponse|null> {
    const resp : GetResultsResponse = new GetResultsResponse()
    try {
        const response = await axios.get<PublishedResults>(resultsEndpoint(election_id))
        resp.status_code = response.status
        if (response.status == 200) {
            resp.results = response.data
        }
    } catch (error) {
        console.log("results get error", error)
        return null;
    }

    return resp;
}

// publishResults publishes an election's results, signed by the user: body is from
// encodeResultsBody. The server builds the election's hash tree and rejects results that don't
// match it (400). Publishing the same results again is a 200, and different ones are a 409.
export async function publishResults(election_id : string, body : string) : Promise<PublishResultsResponse|null> {
    const endpoint = resultsEndpoint(election_id)

    const request_config = await getConfigForAuthenticatedRequest(PUBLISH_RESULTS_ACTION, CertificateRole.global_admin, null, body)
    if (request_config === null) {
        return null;
    }

    const resp : PublishResultsResponse = new PublishResultsResponse()
    try {
        const response = await axios.post(endpoint, body, request_config)
        resp.status_code = response.status
    } catch (error) {
        console.log("results post error", error)
        return null;
    }

    return resp;
}

// ProofLeaf is a published vote in an election's hash tree, with its position in the tree and the
// path that rebuilds the root from it: the sibling of each node from the vote up to the root
export interface ProofLeaf {
    position: number;
    nonce: string;
    vote: string;
    signature: string;
    path: TreeNode[];
}

// VoteProof is the proof for a nonce: the vote with the nonce if it's in the tree, and otherwise the
// votes on either side of where it would be
export interface VoteProof {
    leaves: ProofLeaf[];
}

export class GetVoteProofResponse {
    status_code: number = 200;
    proof: VoteProof|null = null;
}

// getVoteProof fetches the proof from an election's hash tree for the vote with the nonce, which is a
// 404 until the election's results are published. It tells the server which vote is being checked.
// It isn't authenticated, so it isn't directly tied to the user's account, but the server can link
// it to the account through the authenticated requests around it, like the one for the user's
// recovery record.
export async function getVoteProof(election_id : string, nonce : string) : Promise<GetVoteProofResponse|null> {
    const endpoint = "/api/v1/elections/" + encodeURIComponent(election_id) + "/votes/" + encodeURIComponent(nonce) + "/proof"

    const resp : GetVoteProofResponse = new GetVoteProofResponse()
    try {
        const response = await axios.get<VoteProof>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.proof = response.data
        }
    } catch (error) {
        console.log("vote proof get error", error)
        return null;
    }

    return resp;
}
