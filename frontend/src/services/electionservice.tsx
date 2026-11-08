import { CertificateRole } from "@/models/certificate"
import { canonicalJSON, getConfigForAuthenticatedRequest, SignedRequest } from "@/utils/auth"
import axios from "axios"

export interface Candidate {
    id: string;
    position: number;
    name: string;
    description: string;
}

export interface Election {
    id: string;
    jurisdiction_id: string;
    title: string;
    description: string;
    time_open: number;
    time_close: number;
    created_timestamp: number;
    public_key: string;
    // in ballot order
    candidates: Candidate[];
    // signed_request is the admin's request that created the election, which certifies its key (see
    // verifyElectionCreation)
    signed_request: SignedRequest;
}

// ElectionSummary is an election as it appears in lists
export interface ElectionSummary {
    id: string;
    title: string;
    time_open: number;
    time_close: number;
}

export interface NewCandidate {
    name: string;
    description: string;
}

export interface NewElection {
    id: string;
    title: string;
    description: string;
    time_open: number;
    time_close: number;
    // an unclaimed key from createElectionKey
    public_key: string;
    // in ballot order
    candidates: NewCandidate[];
}

export class CreateElectionKeyResponse {
    status_code: number = 201;
    public_key: string = "";
}

export class CreateElectionResponse {
    status_code: number = 201;
    election: Election|null = null;
}

export class GetElectionResponse {
    status_code: number = 200;
    election: Election|null = null;
}

export class GetElectionsResponse {
    status_code: number = 200;
    elections: ElectionSummary[] = [];
}

export type ElectionStatus = "upcoming" | "open" | "closed"

// electionStatus returns whether the election is upcoming, open, or closed at now (a Unix timestamp
// in seconds)
export function electionStatus(election : { time_open: number, time_close: number }, now : number) : ElectionStatus {
    if (now < election.time_open) {
        return "upcoming"
    }
    if (now < election.time_close) {
        return "open"
    }
    return "closed"
}

function jurisdictionElectionsEndpoint(jurisdiction_id : string) : string {
    return "/api/v1/jurisdictions/" + encodeURIComponent(jurisdiction_id) + "/elections"
}

// ELECTION_KEY_VARIANT is the RSA blind signature variant (RFC 9474) that election keys are used
// with. Requests to create elections state it, so the signed request records the key's only use.
export const ELECTION_KEY_VARIANT = "RSABSSA-SHA384-PSS-Randomized"

// CREATE_ELECTION_ACTION is the action of the signed request that creates an election
export const CREATE_ELECTION_ACTION = "election.create"

// createElectionKey has the server generate a key for an election that hasn't been created yet. The
// key is unclaimed until a request to create an election includes its public key.
export async function createElectionKey(jurisdiction_id : string) : Promise<CreateElectionKeyResponse|null> {
    // the jurisdiction is in the URL too, but the URL isn't signed, so the signed request needs it to
    // say which jurisdiction the key is for
    const body = canonicalJSON({ jurisdiction_id })
    const endpoint = "/api/v1/jurisdictions/" + encodeURIComponent(jurisdiction_id) + "/election-keys"

    const request_config = await getConfigForAuthenticatedRequest("election_key.create", CertificateRole.global_admin, null, body)
    if (request_config === null) {
        return null;
    }

    const resp : CreateElectionKeyResponse = new CreateElectionKeyResponse()
    try {
        const response = await axios.post<{ public_key: string }>(endpoint, body, request_config)
        resp.status_code = response.status
        if (response.status == 201) {
            resp.public_key = response.data.public_key
        }
    } catch (error) {
        console.log("election key post error", error)
        return null;
    }

    return resp;
}

export async function createElection(jurisdiction_id : string, election : NewElection) : Promise<CreateElectionResponse|null> {
    // the caller generates the election's id and the candidates' ids are generated here, so the
    // signed request covers every id that votes will reference. it also covers the jurisdiction (the
    // URL isn't signed), and the election key and the variant it will be used with, which certifies
    // the key for the election
    const body = canonicalJSON({
        id: election.id,
        jurisdiction_id,
        title: election.title,
        description: election.description,
        time_open: election.time_open,
        time_close: election.time_close,
        public_key: election.public_key,
        variant: ELECTION_KEY_VARIANT,
        candidates: election.candidates.map(candidate => ({
            id: crypto.randomUUID(),
            name: candidate.name,
            description: candidate.description,
        })),
    })
    const endpoint = jurisdictionElectionsEndpoint(jurisdiction_id)

    const request_config = await getConfigForAuthenticatedRequest(CREATE_ELECTION_ACTION, CertificateRole.global_admin, null, body)
    if (request_config === null) {
        return null;
    }

    const resp : CreateElectionResponse = new CreateElectionResponse()
    try {
        const response = await axios.post<Election>(endpoint, body, request_config)
        resp.status_code = response.status
        if (response.status == 201) {
            resp.election = response.data
        }
    } catch (error) {
        console.log("election post error", error)
        return null;
    }

    return resp;
}

export async function getElections(jurisdiction_id : string) : Promise<GetElectionsResponse|null> {
    const endpoint = jurisdictionElectionsEndpoint(jurisdiction_id)

    const resp : GetElectionsResponse = new GetElectionsResponse()
    try {
        const response = await axios.get<ElectionSummary[]>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.elections = response.data
        }
    } catch (error) {
        console.log("elections get error", error)
        return null;
    }

    return resp;
}

export async function getElection(id : string) : Promise<GetElectionResponse|null> {
    const endpoint = "/api/v1/elections/" + encodeURIComponent(id)

    const resp : GetElectionResponse = new GetElectionResponse()
    try {
        const response = await axios.get<Election>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.election = response.data
        }
    } catch (error) {
        console.log("election get error", error)
        return null;
    }

    return resp;
}
