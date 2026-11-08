import { CertificateRole } from "@/models/certificate"
import { getConfigForAuthenticatedRequest } from "@/utils/auth"
import axios from "axios"

export interface AccountSearchResult {
    username: string;
    public_key: string;
}

export class SearchAccountsResponse {
    status_code: number = 200;
    accounts: AccountSearchResult[] = [];
}

// searchAccounts finds accounts whose usernames start with username (ignoring case)
export async function searchAccounts(username : string) : Promise<SearchAccountsResponse|null> {
    const endpoint = "/api/v1/accounts?" + new URLSearchParams({ username }).toString()

    const request_config = await getConfigForAuthenticatedRequest("account.search", CertificateRole.global_admin, null, "")
    if (request_config === null) {
        return null;
    }

    const resp : SearchAccountsResponse = new SearchAccountsResponse()
    try {
        const response = await axios.get<AccountSearchResult[]>(endpoint, request_config)
        resp.status_code = response.status
        if (response.status == 200) {
            resp.accounts = response.data
        }
    } catch (error) {
        console.log("accounts search error", error)
        return null;
    }

    return resp;
}
