import { readFileSync } from "fs"
import { resolve } from "path"
import { CertificateRole } from "../models/certificate"
import { Election } from "../services/electionservice"
import { Jurisdiction } from "../services/jurisdictionservice"
import { RootCertificate } from "../services/rootcertificateservice"
import { VoterAuthorization } from "../services/voterservice"
import { BlindSignatureRequest, PublishedResults, PublishedVote, VoteProof } from "../services/voteservice"
import { SignedRequest, signedData } from "./auth"
import { arrayBufferToBase64, base64ToArrayBuffer } from "./base64"

// VectorSigner is one of the vectors' users: their public key and the certificate the vectors' root
// issued them, with their private key (PKCS #8 PEM). The keys are throwaway ones, and the private key
// is only there so tests can sign more requests as the user.
export interface VectorSigner {
    public_key: string;
    private_key: string;
    cert_pem: string;
}

// Vectors are a small election's published votes, with the results that publish them and the proofs
// the API serves for them, and the signed requests behind it all, as the API serves them. The API's
// tests write them (TestVectors in backend/route/v1/election/vote), so the tests here check that the
// browser builds and checks the same tree as the server, and accepts the requests and certificates
// it makes.
export interface Vectors {
    election_id: string;
    // public_key is the election key that signed the votes
    public_key: string;
    // votes are in nonce order
    votes: PublishedVote[];
    // results is the body of the admin's request publishing the election's results
    results: string;
    // proofs are what the API serves for each published vote, and for validly signed votes that
    // aren't in the tree
    proofs: { vote: PublishedVote; proof: VoteProof }[];
    // root issued the certificates the requests below were signed under, and other_root is another
    // instance's root
    root: RootCertificate;
    other_root: RootCertificate;
    // admin is the global admin who created the jurisdiction and the election, authorized every voter
    // but the last and published the results, and other_root_admin_cert is a global admin certificate
    // for their key from other_root. second_admin is another global admin, who authorized the last
    // voter.
    admin: VectorSigner;
    other_root_admin_cert: string;
    second_admin: VectorSigner;
    // voters are the election's voters, one for each vote, in the order they were authorized
    voters: VectorSigner[];
    // the rest are what the API serves for them
    jurisdiction: Jurisdiction;
    election: Election;
    voter_authorizations: VoterAuthorization[];
    blind_signature_requests: BlindSignatureRequest[];
    published_results: PublishedResults;
}

// VECTOR_CANDIDATE_IDS are the candidates the vectors' votes are for
export const VECTOR_CANDIDATE_IDS = [
    "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
    "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d",
    "3d6f5a1b-2c4e-4f8a-9b7c-0e1d2f3a4b5c",
]

// loadVectors reads the vectors. Tests run from the frontend directory, which the path is relative to.
export function loadVectors() : Vectors {
    return JSON.parse(readFileSync(resolve("../backend/route/v1/election/vote/testdata/vectors.json"), "utf8"))
}

// vectorElection returns the election the vectors' votes are in
export function vectorElection(vectors : Vectors) : Election {
    return structuredClone(vectors.election)
}

// UnsignedRequest is a request for signAs to sign: what it does, the role and jurisdiction the signer
// acts under, its body, and the instance it's for
export interface UnsignedRequest {
    action: string;
    role: CertificateRole | null;
    jurisdiction_id: string | null;
    body: string;
    instance: string;
    // request_timestamp is now if it isn't given
    request_timestamp?: string;
}

// signAs signs a request as one of the vectors' users, the way their client does, and returns it as
// the API would store it, with their certificate
export async function signAs(signer : VectorSigner, request : UnsignedRequest) : Promise<SignedRequest> {
    const private_key = await crypto.subtle.importKey(
        "pkcs8",
        base64ToArrayBuffer(signer.private_key.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "")),
        { name: "ECDSA", namedCurve: "P-384" },
        false,
        ["sign"],
    )
    const request_timestamp = request.request_timestamp ?? Date.now().toString()
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        private_key,
        new TextEncoder().encode(signedData(request.action, request.instance, request.role, request.jurisdiction_id, request_timestamp, request.body)),
    )

    return {
        action: request.action,
        instance: request.instance,
        role: request.role,
        jurisdiction_id: request.jurisdiction_id,
        request_timestamp,
        body: request.body,
        public_key: signer.public_key,
        signature: arrayBufferToBase64(signature),
        cert_pem: signer.cert_pem,
    }
}

// accepted returns the names of the cases that check accepts rather than rejecting
export async function accepted<T>(cases : Record<string, T>, check : (value : T) => Promise<unknown>) : Promise<string[]> {
    const names : string[] = []
    for (const name of Object.keys(cases)) {
        if (await check(cases[name]).then(() => true, () => false)) {
            names.push(name)
        }
    }

    return names
}
