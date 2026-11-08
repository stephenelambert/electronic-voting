import { CertificateRole } from "@/models/certificate";
import { CREATE_ELECTION_ACTION, Election, ELECTION_KEY_VARIANT } from "@/services/electionservice";
import { CREATE_JURISDICTION_ACTION, Jurisdiction } from "@/services/jurisdictionservice";
import { AUTHORIZE_VOTER_ACTION, VoterAuthorization } from "@/services/voterservice";
import { BlindSignatureRequest, REQUEST_BLIND_SIGNATURE_ACTION } from "@/services/voteservice";
import { SignedRequest, verifySignedRequest } from "@/utils/auth";
import { arrayBufferToBase64, base64ToArrayBuffer } from "@/utils/base64";
import { checkElectionPublicKey, publicKeyHash, publicKeyPEMToDER } from "@/utils/keys";
import { publicKeyDER, Root, signedBy } from "@/utils/root";
import { equalBytes, parseCertificate } from "@/utils/x509";

// CANONICAL_UUID matches a UUID in canonical form, which is how certificates name jurisdictions
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// certificateCommonName returns the common name the API gives certificates for the role in the
// jurisdiction (see localcrypto.CreateCertificateTemplate), for the roles that sign requests
function certificateCommonName(role : CertificateRole, jurisdiction_id : string | null) : string {
    let prefix : string
    switch (role) {
    case CertificateRole.global_admin:
        if (jurisdiction_id !== null) {
            throw new Error("global admins don't have a jurisdiction")
        }
        return "admin.global"
    case CertificateRole.jurisdiction_admin:
        prefix = "admin"
        break
    case CertificateRole.registrar:
        prefix = "registrar"
        break
    case CertificateRole.voter:
        prefix = "voter"
        break
    default:
        throw new Error("role " + role + " doesn't sign requests")
    }

    if (jurisdiction_id === null || !CANONICAL_UUID.test(jurisdiction_id)) {
        throw new Error("role's jurisdiction isn't a canonical UUID")
    }

    return prefix + "." + jurisdiction_id + ".jurisdiction"
}

// checkCertificate checks that the root issued a certificate to the public key (DER), for the role in
// the jurisdiction. It throws otherwise.
async function checkCertificate(cert_pem : string, root : Root, role : CertificateRole, jurisdiction_id : string | null, public_key : Uint8Array) : Promise<void> {
    const certificate = parseCertificate(cert_pem)
    if (!await signedBy(root.key, certificate)) {
        throw new Error("certificate wasn't issued by the root")
    }
    if (certificate.common_name !== certificateCommonName(role, jurisdiction_id)) {
        throw new Error("certificate isn't for the role and jurisdiction")
    }
    if (!equalBytes(certificate.public_key, public_key)) {
        throw new Error("certificate is for another key")
    }
}

// checkSigner checks who signed a stored request. It throws unless the request's signature verifies
// under the key stored with it, it was signed for this instance (the root's), and the root issued its
// certificate to that key, for the role and jurisdiction the request names. checkRequest also checks
// what it was signed for.
export async function checkSigner(signed_request : SignedRequest, root : Root) : Promise<void> {
    if (signed_request.instance !== root.instance) {
        throw new Error("request was signed for another instance")
    }
    if (!await verifySignedRequest(signed_request)) {
        throw new Error("request's signature is invalid")
    }
    if (signed_request.role == null || signed_request.cert_pem == null) {
        throw new Error("request wasn't signed under a certificate")
    }

    await checkCertificate(signed_request.cert_pem, root, signed_request.role, signed_request.jurisdiction_id, publicKeyDER(signed_request.public_key))
}

// checkRequest checks a stored request: that it was signed for the action, acting under the role and
// jurisdiction the action needs, by a key the root certified for them (see checkSigner). For the MVP
// each action needs exactly one, as the API's routes do: admins' actions need a global admin, and
// voters' actions a voter in the election's jurisdiction. It throws otherwise.
export async function checkRequest(signed_request : SignedRequest, root : Root, action : string, role : CertificateRole, jurisdiction_id : string | null) : Promise<void> {
    if (signed_request.action !== action) {
        throw new Error("request was signed for another action")
    }
    if (signed_request.role !== role || signed_request.jurisdiction_id !== jurisdiction_id) {
        throw new Error("request wasn't signed by a " + role + (jurisdiction_id == null ? "" : " in jurisdiction " + jurisdiction_id))
    }

    await checkSigner(signed_request, root)
}

// FieldType is the type of a field in a signed request's body
type FieldType = "string" | "integer" | "array"

// hasType reports whether a value from a signed request's body has the type
function hasType(value : unknown, type : FieldType) : boolean {
    if (type == "integer") {
        return typeof value === "number" && Number.isSafeInteger(value)
    }
    if (type == "array") {
        return Array.isArray(value)
    }

    return typeof value === "string"
}

// exactObject checks that a value from a signed request's body is an object with exactly the fields
// in types, each of its type, so it means the same thing here as it did to the API, and returns it.
// Bodies are compared field by field with what the API serves, rather than re-encoded and compared
// byte for byte, since names and descriptions are free text that Go and the browser encode
// differently.
function exactObject(value : unknown, types : Record<string, FieldType>) : Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("request's body isn't an object")
    }
    const object = value as Record<string, unknown>

    const names = Object.keys(types)
    const keys = Object.keys(object)
    if (keys.length != names.length || keys.some(key => names.indexOf(key) < 0)) {
        throw new Error("request's body doesn't have exactly the fields it should")
    }
    for (const name of names) {
        if (!hasType(object[name], types[name])) {
            throw new Error("request's body has a " + name + " of the wrong type")
        }
    }

    return object
}

// parseBody parses a signed request's body, which must be a JSON object with exactly the fields in
// types (see exactObject)
function parseBody(signed_request : SignedRequest, types : Record<string, FieldType>) : Record<string, unknown> {
    return exactObject(JSON.parse(signed_request.body), types)
}

// numbered adds which item in a list it's about to an error's message
function numbered(item : string, index : number, error : unknown) : Error {
    return new Error(item + " " + (index + 1) + ": " + (error instanceof Error ? error.message : String(error)))
}

// verifyJurisdictionCreation checks the request that created a jurisdiction: that a global admin
// signed it (see checkRequest) to create the jurisdiction, with the ID, name and info it has. It
// throws otherwise.
export async function verifyJurisdictionCreation(jurisdiction : Jurisdiction, root : Root) : Promise<void> {
    const signed_request = jurisdiction.signed_request
    await checkRequest(signed_request, root, CREATE_JURISDICTION_ACTION, CertificateRole.global_admin, null)

    const body = parseBody(signed_request, { id: "string", info: "string", name: "string" })
    if (body.id !== jurisdiction.id || body.name !== jurisdiction.name || body.info !== jurisdiction.info) {
        throw new Error("jurisdiction isn't the one its request created")
    }
}

// verifyElectionCreation checks the request that created an election: that a global admin signed it
// (see checkRequest) to create the election in its jurisdiction, with the title, description, times
// and candidates it has, in ballot order, and with its key. The request also names the blind
// signature variant the key is for, so once it checks out, the key can be trusted for the election.
// It throws otherwise.
export async function verifyElectionCreation(election : Election, root : Root) : Promise<void> {
    const signed_request = election.signed_request
    await checkRequest(signed_request, root, CREATE_ELECTION_ACTION, CertificateRole.global_admin, null)

    const body = parseBody(signed_request, {
        id: "string",
        jurisdiction_id: "string",
        title: "string",
        description: "string",
        time_open: "integer",
        time_close: "integer",
        public_key: "string",
        variant: "string",
        candidates: "array",
    })
    if (body.id !== election.id || body.jurisdiction_id !== election.jurisdiction_id || body.title !== election.title
        || body.description !== election.description || body.time_open !== election.time_open || body.time_close !== election.time_close) {
        throw new Error("election isn't the one its request created")
    }
    if (body.variant !== ELECTION_KEY_VARIANT || !equalBytes(publicKeyDER(body.public_key as string), publicKeyDER(election.public_key))) {
        throw new Error("election's key isn't the one its request certified")
    }

    const candidates = body.candidates as unknown[]
    if (candidates.length != election.candidates.length) {
        throw new Error("election's candidates aren't the ones its request created")
    }
    candidates.forEach((value, position) => {
        const candidate = exactObject(value, { id: "string", name: "string", description: "string" })
        const served = election.candidates[position]
        if (served.position !== position || candidate.id !== served.id || candidate.name !== served.name || candidate.description !== served.description) {
            throw new Error("election's candidates aren't the ones its request created")
        }
    })
}

// checkElectionKey checks an election's key before it's used to blind or check votes: that it's the
// key a global admin created the election with (see verifyElectionCreation), and that it's fit for
// signing votes (see checkElectionPublicKey). It resolves to the key, ready to check votes'
// signatures, and throws otherwise.
export async function checkElectionKey(election : Election, root : Root) : Promise<CryptoKey> {
    await verifyElectionCreation(election, root)
    return await checkElectionPublicKey(election.public_key)
}

// checkVoterAuthorization checks that a global admin signed authorization (see checkRequest) to
// authorize a key to vote in the jurisdiction, and that the root issued that key the voter
// certificate. It resolves to the key, as base64 DER, which is the same however its PEM is laid out.
async function checkVoterAuthorization(authorization : SignedRequest, cert_pem : string, jurisdiction_id : string, root : Root) : Promise<string> {
    await checkRequest(authorization, root, AUTHORIZE_VOTER_ACTION, CertificateRole.global_admin, null)

    const body = parseBody(authorization, { jurisdiction_id: "string", public_key: "string" })
    if (body.jurisdiction_id !== jurisdiction_id) {
        throw new Error("voter was authorized in another jurisdiction")
    }
    // the admin's client signs the key as the API sent it, so it's compared with the certificate's
    // as DER
    const public_key : ArrayBuffer = publicKeyPEMToDER(body.public_key as string)
    await checkCertificate(cert_pem, root, CertificateRole.voter, jurisdiction_id, new Uint8Array(public_key))

    return arrayBufferToBase64(public_key)
}

// verifyVoterAuthorization checks a voter authorization: that its certificate is listed as a voter
// certificate for the jurisdiction, and that the root issued it to a key a global admin authorized to
// vote there (see checkVoterAuthorization). It resolves to the voter's key, as base64 DER, which is
// the same however its PEM is laid out, and throws if the authorization doesn't check out.
export async function verifyVoterAuthorization(jurisdiction_id : string, voter_authorization : VoterAuthorization, root : Root) : Promise<string> {
    const { certificate, authorization } = voter_authorization
    if (certificate.role !== CertificateRole.voter || certificate.jurisdiction_id !== jurisdiction_id) {
        throw new Error("certificate isn't listed as a voter certificate for the jurisdiction")
    }

    return await checkVoterAuthorization(authorization, certificate.cert_pem, jurisdiction_id, root)
}

// Authorizer is a global admin's key that authorized voters, and how many of the voters an audit
// found it authorized. The API's host holds the root key, so it could issue a global admin
// certificate to a key of its own and authorize voters with it. Listing the keys lets anyone who
// knows the real admins' keys spot one that isn't theirs.
export interface Authorizer {
    // public_key is the admin's key (PEM), as the first of its authorizations has it
    public_key : string;
    voters : number;
    // creator is whether the key also signed the request that created the jurisdiction or election
    // being audited
    creator : boolean;
}

// AuthorizerTally counts the voters each key authorized, keyed by the key's DER (base64), which is
// the same however its PEM is laid out
class AuthorizerTally {
    private readonly authorizers = new Map<string, Authorizer>()
    private readonly creator : string

    // creator_public_key is the key (PEM) that signed the request creating what's being audited
    constructor(creator_public_key : string) {
        this.creator = arrayBufferToBase64(publicKeyPEMToDER(creator_public_key))
    }

    // add counts a voter the key (PEM) authorized
    add(public_key : string) : void {
        const der = arrayBufferToBase64(publicKeyPEMToDER(public_key))
        const authorizer = this.authorizers.get(der)
        if (authorizer === undefined) {
            this.authorizers.set(der, { public_key, voters: 1, creator: der === this.creator })
        } else {
            authorizer.voters++
        }
    }

    // list returns the keys, the one that authorized the most voters first, and keys that authorized
    // as many in the order they were first seen
    list() : Authorizer[] {
        return Array.from(this.authorizers.values()).sort((a, b) => b.voters - a.voters)
    }
}

// VoterAuthorizationAudit is what auditVoterAuthorizations finds in a jurisdiction's published voter
// authorizations
export interface VoterAuthorizationAudit {
    // voters is how many voters they authorize
    voters : number;
    // authorizers are the keys that authorized them (see Authorizer), and creator marks the one that
    // created the jurisdiction
    authorizers : Authorizer[];
}

// auditVoterAuthorizations checks a jurisdiction's published voter authorizations, and counts the
// voters they authorize and the voters each admin's key authorized. Each must check out (see
// verifyVoterAuthorization), and since a key has at most one active voter certificate in a
// jurisdiction, no key can be listed twice. It throws if an authorization doesn't check out, saying
// which. It doesn't check the request that created the jurisdiction (see verifyJurisdictionCreation),
// which marking its key relies on.
export async function auditVoterAuthorizations(jurisdiction : Jurisdiction, authorizations : VoterAuthorization[], root : Root) : Promise<VoterAuthorizationAudit> {
    const voters = new Set<string>()
    const authorizers = new AuthorizerTally(jurisdiction.signed_request.public_key)
    for (let i = 0; i < authorizations.length; i++) {
        try {
            const voter = await verifyVoterAuthorization(jurisdiction.id, authorizations[i], root)
            if (voters.has(voter)) {
                throw new Error("voter is listed more than once")
            }
            voters.add(voter)
            authorizers.add(authorizations[i].authorization.public_key)
        } catch (error) {
            throw numbered("voter authorization", i, error)
        }
    }

    return { voters: voters.size, authorizers: authorizers.list() }
}

// BlindSignatureAudit is what auditBlindSignatureRequests finds in an election's published requests
// for blind signatures
export interface BlindSignatureAudit {
    // counted is how many of the requests count toward the votes the election can have. Each voter's
    // key and each blinded message counts once, so neither a voter's second request nor a request
    // copied under another key counts.
    counted : number;
    // authorizers are the keys that authorized the voters of the counted requests (see Authorizer),
    // and creator marks the one that created the election
    authorizers : Authorizer[];
    // other_key are the requests that name a key other than the election's, which aren't counted.
    // Their voters signed them, so they show the server gave those voters a different key, which
    // could let it recognize their votes.
    other_key : BlindSignatureRequest[];
}

// auditBlindSignatureRequests checks an election's published requests for blind signatures, and
// counts them (see BlindSignatureAudit). Each must be signed (see checkRequest) by a voter in the
// election's jurisdiction, for the election, and come with a global admin's request authorizing that
// voter's key (see checkVoterAuthorization). It throws if a request doesn't check out, saying which.
// It doesn't check the request that created the election (see checkElectionKey), which marking its
// key relies on.
export async function auditBlindSignatureRequests(election : Election, requests : BlindSignatureRequest[], root : Root) : Promise<BlindSignatureAudit> {
    const key_hash = await publicKeyHash(election.public_key)
    const audit : BlindSignatureAudit = { counted: 0, authorizers: [], other_key: [] }
    const authorizers = new AuthorizerTally(election.signed_request.public_key)
    const voters = new Set<string>()
    const messages = new Set<string>()

    for (let i = 0; i < requests.length; i++) {
        const { signed_request, authorization } = requests[i]
        try {
            await checkRequest(signed_request, root, REQUEST_BLIND_SIGNATURE_ACTION, CertificateRole.voter, election.jurisdiction_id)

            const body = parseBody(signed_request, { election_id: "string", blinded_message: "string", public_key_hash: "string" })
            if (body.election_id !== election.id) {
                throw new Error("request is for another election")
            }
            // decoded and encoded again, so a message is the same string however it was encoded
            const message = arrayBufferToBase64(base64ToArrayBuffer(body.blinded_message as string))

            // checkRequest showed the root issued the request's certificate to its key, so this shows a
            // global admin authorized that key
            const voter = await checkVoterAuthorization(authorization, signed_request.cert_pem as string, election.jurisdiction_id, root)

            if (body.public_key_hash !== key_hash) {
                audit.other_key.push(requests[i])
            } else if (!voters.has(voter) && !messages.has(message)) {
                voters.add(voter)
                messages.add(message)
                audit.counted++
                authorizers.add(authorization.public_key)
            }
        } catch (error) {
            throw numbered("blind signature request", i, error)
        }
    }

    audit.authorizers = authorizers.list()
    return audit
}
