import axios from "axios";
import { SimpleCertificate } from "@/models/certificate";
import { getConfigForAuthenticatedRequest } from "@/utils/auth";
import { getUser, saveUser } from "@/utils/user";

export class GetCertificatesResponse {
    status_code: number = 0;
    success: boolean = false;
    certificates: SimpleCertificate[] = [];
}

export async function getMyCertificates() : Promise<GetCertificatesResponse> {
    const get_response : GetCertificatesResponse = new GetCertificatesResponse();

    const endpoint = "/api/v1/certificates/my"

    const request_config = await getConfigForAuthenticatedRequest("certificate.list_own", null, null, "")
    if (request_config === null) {
        console.log("error getting config for authenticated request")
        get_response.status_code = 0;
        return get_response;
    }

    try {
        const response = await axios.get(endpoint, request_config);

        get_response.status_code = response.status;

        if (response.status != 200) {
            return get_response;
        }

        get_response.certificates = response.data;
        get_response.success = true;
    } catch (error) {
        console.log("getMyCertificates error", error)

        return get_response;
    }

    return get_response;
}

async function startupGetCerts() : Promise<void> {
    const cert_resp = await getMyCertificates();

    if (cert_resp.success) {
        const user = await getUser();
        if (user !== null) {
            user.certificates = cert_resp.certificates;
            await saveUser(user);
        }
    }
}

// fetch the user's certificates on application load/refresh
startupGetCerts();