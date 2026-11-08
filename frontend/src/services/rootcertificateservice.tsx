import axios from "axios"

// RootCertificate is the API's root certificate, which signs every other certificate, and its public
// key. Signed requests name the instance they're for with the hash of the key.
export interface RootCertificate {
    cert_pem: string;
    public_key: string;
}

export class GetRootCertificateResponse {
    status_code: number = 200;
    root: RootCertificate|null = null;
}

// getRootCertificate fetches the API's root certificate
export async function getRootCertificate() : Promise<GetRootCertificateResponse|null> {
    const endpoint = "/api/v1/certificates/root"

    const resp : GetRootCertificateResponse = new GetRootCertificateResponse()
    try {
        const response = await axios.get<RootCertificate>(endpoint)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.root = response.data
        }
    } catch (error) {
        console.log("root certificate get error", error)
        return null;
    }

    return resp;
}
