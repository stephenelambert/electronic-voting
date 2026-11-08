import { CertificateRole, SimpleCertificate } from "@/models/certificate"
import { canonicalJSON, getConfigForAuthenticatedRequest, SignedRequest } from "@/utils/auth"
import axios from "axios"

export interface Voter {
    username: string;
    public_key: string;
    authorized_timestamp: number;
    certificate: SimpleCertificate;
    // authorization is the admin's signed request that authorized the voter, which is also published
    // (see getVoterAuthorizations)
    authorization: SignedRequest;
}

// VoterAuthorization is a published voter authorization: a voter's certificate, and the admin's
// signed request that authorized it (see auditVoterAuthorizations). Both name the voter by key, not
// by username.
export interface VoterAuthorization {
    certificate: SimpleCertificate;
    authorization: SignedRequest;
}

// AUTHORIZE_VOTER_ACTION is the action of the signed request that authorizes a voter in a jurisdiction
export const AUTHORIZE_VOTER_ACTION = "voter.authorize"

interface VotersPage {
    total: number;
    voters: Voter[];
}

export interface GetVotersOptions {
    limit: number;
    offset: number;
    username?: string;
}

export class GetVotersResponse {
    status_code: number = 200;
    total: number = 0;
    voters: Voter[] = [];
}

export class AuthorizeVoterResponse {
    status_code: number = 201;
    certificate: SimpleCertificate|null = null;
}

export class GetVoterAuthorizationsResponse {
    status_code: number = 200;
    // in the order they were issued
    authorizations: VoterAuthorization[] = [];
}

function votersEndpoint(jurisdiction_id : string) : string {
    return "/api/v1/jurisdictions/" + encodeURIComponent(jurisdiction_id) + "/voters"
}

// getVoterAuthorizations fetches every published voter authorization in the jurisdiction, one for
// each voter, so it can be large
export async function getVoterAuthorizations(jurisdiction_id : string) : Promise<GetVoterAuthorizationsResponse|null> {
    const endpoint = "/api/v1/jurisdictions/" + encodeURIComponent(jurisdiction_id) + "/voter-authorizations"

    const resp : GetVoterAuthorizationsResponse = new GetVoterAuthorizationsResponse()
    try {
        const response = await axios.get<VoterAuthorization[]>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.authorizations = response.data
        }
    } catch (error) {
        console.log("voter authorizations get error", error)
        return null;
    }

    return resp;
}

export async function getVoters(jurisdiction_id : string, options : GetVotersOptions) : Promise<GetVotersResponse|null> {
    const params = new URLSearchParams({
        limit: options.limit.toString(),
        offset: options.offset.toString(),
    })
    if (options.username) {
        params.set("username", options.username)
    }
    const endpoint = votersEndpoint(jurisdiction_id) + "?" + params.toString()

    const request_config = await getConfigForAuthenticatedRequest("voter.list", CertificateRole.global_admin, null, "")
    if (request_config === null) {
        return null;
    }

    const resp : GetVotersResponse = new GetVotersResponse()
    try {
        const response = await axios.get<VotersPage>(endpoint, request_config)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.total = response.data.total
            resp.voters = response.data.voters
        }
    } catch (error) {
        console.log("voters get error", error)
        return null;
    }

    return resp;
}

export async function authorizeVoter(jurisdiction_id : string, public_key : string) : Promise<AuthorizeVoterResponse|null> {
    // the jurisdiction is in the URL too, but the URL isn't signed, so the signed request needs it to
    // say where the voter is authorized
    const body = canonicalJSON({ jurisdiction_id, public_key })
    const endpoint = votersEndpoint(jurisdiction_id)

    const request_config = await getConfigForAuthenticatedRequest(AUTHORIZE_VOTER_ACTION, CertificateRole.global_admin, null, body)
    if (request_config === null) {
        return null;
    }

    const resp : AuthorizeVoterResponse = new AuthorizeVoterResponse()
    try {
        const response = await axios.post<SimpleCertificate>(endpoint, body, request_config)
        resp.status_code = response.status
        if (response.status == 201) {
            resp.certificate = response.data
        }
    } catch (error) {
        console.log("voter post error", error)
        return null;
    }

    return resp;
}
