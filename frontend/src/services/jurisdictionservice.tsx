import { CertificateRole } from "@/models/certificate"
import { canonicalJSON, getConfigForAuthenticatedRequest, SignedRequest } from "@/utils/auth"
import axios from "axios"

// JurisdictionSummary is a jurisdiction as it appears in lists
export interface JurisdictionSummary {
    id: string;
    info: string;
    name: string;
    created_timestamp: number;
}

export interface Jurisdiction extends JurisdictionSummary {
    // signed_request is the admin's request that created the jurisdiction (see
    // verifyJurisdictionCreation)
    signed_request: SignedRequest;
}

// CREATE_JURISDICTION_ACTION is the action of the signed request that creates a jurisdiction
export const CREATE_JURISDICTION_ACTION = "jurisdiction.create"

export class CreateJurisdictionResponse {
    status_code: number = 200;
    jurisdiction_id: string = "";
}

export class GetJurisdictionResponse {
    status_code: number = 200;
    jurisdiction: Jurisdiction|null = null;
}

export class GetJurisdictionsResponse {
    status_code: number = 200;
    jurisdictions: JurisdictionSummary[] = [];
}

export async function createJurisdiction(id : string, name : string, info : string) : Promise<CreateJurisdictionResponse|null> {

    // get the body into a string, with the fields in the order the API's canonical encoding needs
    const data = {
        // the caller generates the id, so the signed request covers the new jurisdiction's id
        id: id,
        name: name,
        info: info,
    }
    const body = canonicalJSON(data)

    const endpoint = "/api/v1/jurisdictions"

    const request_config = await getConfigForAuthenticatedRequest(CREATE_JURISDICTION_ACTION, CertificateRole.global_admin, null, body)
    if (request_config === null) {
        return null;
    }

    const resp : CreateJurisdictionResponse = new CreateJurisdictionResponse()
    try {
        const response = await axios.post<Jurisdiction>(endpoint, body, request_config)
        resp.status_code = response.status

        // error responses have no body, so only read the jurisdiction on success
        if (response.status == 200) {
            const jurisdiction_obj : Jurisdiction = response.data
            resp.jurisdiction_id = jurisdiction_obj.id
        }
    } catch (error) {
        console.log("jurisdiction post error", error)
        return null;
    }

    return resp;
}

export async function getJurisdiction(id : string) : Promise<GetJurisdictionResponse|null> {
    const endpoint = "/api/v1/jurisdictions/" + id;

    const resp : GetJurisdictionResponse = new GetJurisdictionResponse()
    try {
        const response = await axios.get<Jurisdiction>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.jurisdiction = response.data
        }
    } catch (error) {
        console.log("jurisdiction get error", error)
        return null;
    }

    return resp;
}

export async function getJurisdictions() : Promise<GetJurisdictionsResponse|null> {
    const endpoint = "/api/v1/jurisdictions";

    const resp : GetJurisdictionsResponse = new GetJurisdictionsResponse()
    try {
        const response = await axios.get<JurisdictionSummary[]>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.jurisdictions = response.data
        }
    } catch (error) {
        console.log("jurisdictions get error", error)
        return null;
    }

    return resp;
}