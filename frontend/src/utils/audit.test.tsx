import { describe, expect, it } from "vitest"
import { CertificateRole } from "../models/certificate"
import { CREATE_ELECTION_ACTION, Election } from "../services/electionservice"
import { CREATE_JURISDICTION_ACTION, Jurisdiction } from "../services/jurisdictionservice"
import { AUTHORIZE_VOTER_ACTION, VoterAuthorization } from "../services/voterservice"
import { BlindSignatureRequest, REQUEST_BLIND_SIGNATURE_ACTION } from "../services/voteservice"
import { auditBlindSignatureRequests, auditVoterAuthorizations, Authorizer, checkElectionKey, checkRequest, checkSigner, verifyElectionCreation, verifyJurisdictionCreation, verifyVoterAuthorization } from "./audit"
import { canonicalJSON, SignedRequest } from "./auth"
import { arrayBufferToBase64 } from "./base64"
import { verifyVoteSignature } from "./ballot"
import { publicKeyHash, publicKeyPEMToDER } from "./keys"
import { loadRoot, Root } from "./root"
import { accepted, loadVectors, signAs, Vectors, VectorSigner } from "./testvectors"

// OTHER_ID is a canonical UUID that names nothing in the vectors
const OTHER_ID = "c0ffee00-1234-4abc-8def-0123456789ab"

// asAdmin signs a request as the vectors' global admin
async function asAdmin(vectors : Vectors, root : Root, action : string, body : string) : Promise<SignedRequest> {
    return await signAs(vectors.admin, { action, role: CertificateRole.global_admin, jurisdiction_id: null, body, instance: root.instance })
}

// asVoter signs a request as one of the vectors' voters, acting as a voter in the vectors' jurisdiction
async function asVoter(vectors : Vectors, root : Root, voter : VectorSigner, action : string, body : string) : Promise<SignedRequest> {
    return await signAs(voter, { action, role: CertificateRole.voter, jurisdiction_id: vectors.jurisdiction.id, body, instance: root.instance })
}

// randomMessage returns a random blinded message, in base64
function randomMessage() : string {
    return arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(256)).buffer)
}

// goEscaped returns a JSON body the way Go's encoding/json writes it by default, escaping < > and &,
// which the API's canonical encoding doesn't
function goEscaped(body : string) : string {
    return body.replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")
}

// vectorAuthorizers returns the keys an audit finds authorized the vectors' voters: the admin, who
// created the jurisdiction and the election, authorized admin_voters of them, and the second admin
// the last one
function vectorAuthorizers(vectors : Vectors, admin_voters : number = vectors.voters.length - 1) : Authorizer[] {
    return [
        { public_key: vectors.admin.public_key, voters: admin_voters, creator: true },
        { public_key: vectors.second_admin.public_key, voters: 1, creator: false },
    ]
}

// oneLine lays a PEM public key out on one line between its markers, as another client might
function oneLine(public_key : string) : string {
    return public_key.replace(/\n(?!-----END)/g, "").replace("KEY-----", "KEY-----\n")
}

// allRequests names every signed request in the vectors
function allRequests(vectors : Vectors) : Record<string, SignedRequest> {
    const requests : Record<string, SignedRequest> = {
        "the jurisdiction's creation": vectors.jurisdiction.signed_request,
        "the election's creation": vectors.election.signed_request,
        "the results' publication": vectors.published_results.signed_request,
    }
    vectors.voter_authorizations.forEach((authorization, i) => {
        requests["voter authorization " + (i + 1)] = authorization.authorization
    })
    vectors.blind_signature_requests.forEach((request, i) => {
        requests["blind signature request " + (i + 1)] = request.signed_request
    })

    return requests
}

describe("the vectors' requests", () => {
    it("have bodies in the API's canonical encoding", () => {
        const vectors = loadVectors()
        const requests = allRequests(vectors)

        // the API's tests encoded them, so this also checks that canonicalJSON agrees with the API on
        // the characters in their names and descriptions
        const reencoded = Object.keys(requests).filter(name => canonicalJSON(JSON.parse(requests[name].body)) !== requests[name].body)
        expect(reencoded).toEqual([])
    })
})

describe("checkSigner", () => {
    it("accepts every request in the vectors", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)

        expect(await accepted(allRequests(vectors), request => checkSigner(request, root))).toEqual(Object.keys(allRequests(vectors)))
    })

    it("rejects requests altered after signing", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const signed = vectors.blind_signature_requests[0].signed_request

        const cases : Record<string, SignedRequest> = {
            "another action": { ...signed, action: CREATE_JURISDICTION_ACTION },
            "another instance": { ...signed, instance: (await loadRoot(vectors.other_root)).instance },
            "another role": { ...signed, role: CertificateRole.registrar },
            "another jurisdiction": { ...signed, jurisdiction_id: OTHER_ID },
            "another timestamp": { ...signed, request_timestamp: (Number(signed.request_timestamp) + 1).toString() },
            "another body": { ...signed, body: signed.body.replace(vectors.election.id, OTHER_ID) },
            "another key": { ...signed, public_key: vectors.voters[1].public_key },
            "another request's signature": { ...signed, signature: vectors.blind_signature_requests[1].signed_request.signature },
        }
        expect(await accepted(cases, request => checkSigner(request, root))).toEqual([])
    })

    it("rejects requests without a certificate the root issued their signer", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const other_root = await loadRoot(vectors.other_root)
        const voter = vectors.voters[0]
        const body = vectors.blind_signature_requests[0].signed_request.body
        const sign = (signer : VectorSigner, role : CertificateRole | null, jurisdiction_id : string | null, instance = root.instance) =>
            signAs(signer, { action: REQUEST_BLIND_SIGNATURE_ACTION, role, jurisdiction_id, body, instance })
        const other_root_admin = { ...vectors.admin, cert_pem: vectors.other_root_admin_cert }

        const cases : Record<string, SignedRequest> = {
            "no certificate": { ...await sign(voter, CertificateRole.voter, vectors.jurisdiction.id), cert_pem: null },
            "no role": await sign(voter, null, null),
            "another voter's certificate": { ...await sign(voter, CertificateRole.voter, vectors.jurisdiction.id), cert_pem: vectors.voters[1].cert_pem },
            "a certificate for another role": await sign(voter, CertificateRole.global_admin, null),
            "a certificate for another jurisdiction": await sign(voter, CertificateRole.voter, OTHER_ID),
            "a jurisdiction that isn't canonical": await sign(voter, CertificateRole.voter, vectors.jurisdiction.id.toUpperCase()),
            "a certificate that won't parse": { ...await sign(voter, CertificateRole.voter, vectors.jurisdiction.id), cert_pem: voter.cert_pem.replace("\n-----END", "AA\n-----END") },
            "another root's certificate": await sign(other_root_admin, CertificateRole.global_admin, null),
            "another instance, with its root's certificate": await sign(other_root_admin, CertificateRole.global_admin, null, other_root.instance),
        }
        expect(await accepted(cases, request => checkSigner(request, root))).toEqual([])

        // the other instance's request checks out against its own root
        await checkSigner(cases["another instance, with its root's certificate"], other_root)
    })
})

describe("checkRequest", () => {
    it("accepts requests signed for the action, as the role it needs", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)

        await checkRequest(vectors.election.signed_request, root, CREATE_ELECTION_ACTION, CertificateRole.global_admin, null)
        await checkRequest(vectors.blind_signature_requests[0].signed_request, root, REQUEST_BLIND_SIGNATURE_ACTION, CertificateRole.voter, vectors.jurisdiction.id)
    })

    it("rejects requests signed for another action, or as another role", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const election = vectors.election.signed_request
        const blind = vectors.blind_signature_requests[0].signed_request

        const cases : Record<string, () => Promise<void>> = {
            "another action": () => checkRequest(election, root, CREATE_JURISDICTION_ACTION, CertificateRole.global_admin, null),
            "an admin's request where a voter's is needed": () => checkRequest(election, root, CREATE_ELECTION_ACTION, CertificateRole.voter, vectors.jurisdiction.id),
            "a voter's request where an admin's is needed": () => checkRequest(blind, root, REQUEST_BLIND_SIGNATURE_ACTION, CertificateRole.global_admin, null),
            "a voter in another jurisdiction": () => checkRequest(blind, root, REQUEST_BLIND_SIGNATURE_ACTION, CertificateRole.voter, OTHER_ID),
        }
        expect(await accepted(cases, check => check())).toEqual([])
    })
})

describe("verifyJurisdictionCreation", () => {
    it("accepts the vectors' jurisdiction", async () => {
        const vectors = loadVectors()

        await verifyJurisdictionCreation(vectors.jurisdiction, await loadRoot(vectors.root))
    })

    it("accepts a request body in another encoding", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        // the API only accepts the canonical encoding, but this compares what bodies decode to, so it
        // doesn't depend on that
        const body = goEscaped(vectors.jurisdiction.signed_request.body)
        expect(body).not.toBe(vectors.jurisdiction.signed_request.body)

        await verifyJurisdictionCreation({ ...vectors.jurisdiction, signed_request: await asAdmin(vectors, root, CREATE_JURISDICTION_ACTION, body) }, root)
    })

    it("rejects jurisdictions their requests didn't create", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const jurisdiction = vectors.jurisdiction
        const body = JSON.parse(jurisdiction.signed_request.body)
        const signed = async (request_body : unknown) : Promise<Jurisdiction> =>
            ({ ...jurisdiction, signed_request: await asAdmin(vectors, root, CREATE_JURISDICTION_ACTION, JSON.stringify(request_body)) })

        const cases : Record<string, Jurisdiction> = {
            "another name": { ...jurisdiction, name: jurisdiction.name + "!" },
            "other info": { ...jurisdiction, info: "" },
            "another ID": { ...jurisdiction, id: OTHER_ID },
            "the election's request": { ...jurisdiction, signed_request: vectors.election.signed_request },
            "a request signed by a voter": { ...jurisdiction, signed_request: await asVoter(vectors, root, vectors.voters[0], CREATE_JURISDICTION_ACTION, jurisdiction.signed_request.body) },
            "a body with another field": await signed({ ...body, parent_id: OTHER_ID }),
            "a body without the info": await signed({ id: body.id, name: body.name }),
            "a name that isn't text": await signed({ ...body, name: ["Test County"] }),
            "a body that isn't an object": await signed([body]),
        }
        expect(await accepted(cases, j => verifyJurisdictionCreation(j, root))).toEqual([])
    })
})

describe("verifyElectionCreation", () => {
    it("accepts the vectors' election", async () => {
        const vectors = loadVectors()

        await verifyElectionCreation(vectors.election, await loadRoot(vectors.root))
    })

    it("accepts a request body in another encoding", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const body = goEscaped(vectors.election.signed_request.body)
        expect(body).not.toBe(vectors.election.signed_request.body)

        await verifyElectionCreation({ ...vectors.election, signed_request: await asAdmin(vectors, root, CREATE_ELECTION_ACTION, body) }, root)
    })

    it("accepts the key laid out differently", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const one_line = vectors.election.public_key.replace(/\n(?!-----END)/g, "").replace("KEY-----", "KEY-----\n")
        expect(one_line).not.toBe(vectors.election.public_key)

        await verifyElectionCreation({ ...vectors.election, public_key: one_line }, root)
    })

    it("rejects elections their requests didn't create", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const election = vectors.election
        const candidates = election.candidates
        const body = JSON.parse(election.signed_request.body)
        const signed = async (request_body : unknown) : Promise<Election> =>
            ({ ...election, signed_request: await asAdmin(vectors, root, CREATE_ELECTION_ACTION, JSON.stringify(request_body)) })

        const cases : Record<string, Election> = {
            "another ID": { ...election, id: OTHER_ID },
            "another jurisdiction": { ...election, jurisdiction_id: OTHER_ID },
            "another title": { ...election, title: "" },
            "another description": { ...election, description: election.description + " " },
            "another opening time": { ...election, time_open: election.time_open - 1 },
            "another closing time": { ...election, time_close: election.time_close + 1 },
            "another key": { ...election, public_key: vectors.admin.public_key },
            "a renamed candidate": { ...election, candidates: candidates.map((c, i) => i == 1 ? { ...c, name: "Someone else" } : c) },
            "another candidate description": { ...election, candidates: candidates.map((c, i) => i == 2 ? { ...c, description: "" } : c) },
            "candidates in another order": { ...election, candidates: [candidates[1], candidates[0], candidates[2]].map((c, position) => ({ ...c, position })) },
            "a candidate at another position": { ...election, candidates: candidates.map((c, i) => i == 2 ? { ...c, position: 3 } : c) },
            "a missing candidate": { ...election, candidates: candidates.slice(0, 2) },
            "an extra candidate": { ...election, candidates: [...candidates, { id: OTHER_ID, position: 3, name: "Extra", description: "" }] },
            "the jurisdiction's request": { ...election, signed_request: vectors.jurisdiction.signed_request },
            "a request signed by a voter": { ...election, signed_request: await asVoter(vectors, root, vectors.voters[0], CREATE_ELECTION_ACTION, election.signed_request.body) },
            "another variant": await signed({ ...body, variant: "RSABSSA-SHA384-PSS-Deterministic" }),
            "an opening time as text": await signed({ ...body, time_open: String(body.time_open) }),
            "a body with another field": await signed({ ...body, extra: true }),
            "a candidate with another field": await signed({ ...body, candidates: body.candidates.map((c : object, i : number) => i == 0 ? { ...c, extra: true } : c) }),
            "candidates that aren't a list": await signed({ ...body, candidates: { ...body.candidates } }),
        }
        expect(await accepted(cases, e => verifyElectionCreation(e, root))).toEqual([])
    })
})

describe("checkElectionKey", () => {
    it("returns the key a global admin created the election with", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)

        const election_key = await checkElectionKey(vectors.election, root)

        const [vote] = vectors.votes
        expect(await verifyVoteSignature(election_key, vote.nonce, vote.vote, vote.signature)).toBe(true)
    })

    it("rejects keys that don't check out", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const election = vectors.election
        // an admin certified a key that can't sign votes
        const ec_key = vectors.admin.public_key
        const body = JSON.stringify({ ...JSON.parse(election.signed_request.body), public_key: ec_key })
        const signed_request = await asAdmin(vectors, root, CREATE_ELECTION_ACTION, body)

        const cases : Record<string, Election> = {
            "a key the election wasn't created with": { ...election, public_key: ec_key },
            "a certified key that isn't fit for signing votes": { ...election, public_key: ec_key, signed_request },
        }
        expect(await accepted(cases, e => checkElectionKey(e, root))).toEqual([])
        await verifyElectionCreation(cases["a certified key that isn't fit for signing votes"], root)
    })
})

describe("verifyVoterAuthorization", () => {
    it("returns each voter's key", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)

        for (let i = 0; i < vectors.voters.length; i++) {
            const voter_key = await verifyVoterAuthorization(vectors.jurisdiction.id, vectors.voter_authorizations[i], root)
            expect(voter_key).toBe(arrayBufferToBase64(publicKeyPEMToDER(vectors.voters[i].public_key)))
        }
    })

    it("rejects authorizations for another jurisdiction", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)

        await expect(verifyVoterAuthorization(OTHER_ID, vectors.voter_authorizations[0], root)).rejects.toThrow()
    })
})

describe("auditVoterAuthorizations", () => {
    it("counts the jurisdiction's voters, and the voters each admin's key authorized", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)

        expect(await auditVoterAuthorizations(vectors.jurisdiction, vectors.voter_authorizations, root)).toEqual({
            voters: vectors.voters.length,
            authorizers: vectorAuthorizers(vectors),
        })
        expect(await auditVoterAuthorizations(vectors.jurisdiction, [], root)).toEqual({ voters: 0, authorizers: [] })
    })

    it("accepts a key the admin's client laid out differently", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const [first, ...rest] = vectors.voter_authorizations
        const authorization = await asAdmin(vectors, root, AUTHORIZE_VOTER_ACTION, JSON.stringify({ jurisdiction_id: vectors.jurisdiction.id, public_key: oneLine(vectors.voters[0].public_key) }))

        expect((await auditVoterAuthorizations(vectors.jurisdiction, [{ ...first, authorization }, ...rest], root)).voters).toBe(vectors.voters.length)
    })

    it("counts an admin's key once however it's laid out", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const authorizations = vectors.voter_authorizations
        const [first, second] = authorizations
        // the API stores the key its signer's client sent, so two of an admin's requests can lay it
        // out differently, and so can the one that created the jurisdiction
        const jurisdiction : Jurisdiction = { ...vectors.jurisdiction, signed_request: { ...vectors.jurisdiction.signed_request, public_key: oneLine(vectors.admin.public_key) } }
        const relaid : VoterAuthorization = { ...second, authorization: { ...second.authorization, public_key: oneLine(second.authorization.public_key) } }

        const audit = await auditVoterAuthorizations(jurisdiction, [first, relaid, ...authorizations.slice(2)], root)

        // the key is listed as its first authorization has it
        expect(audit.authorizers).toEqual(vectorAuthorizers(vectors))
    })

    it("marks the key that signed the jurisdiction's creation", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const jurisdiction : Jurisdiction = { ...vectors.jurisdiction, signed_request: { ...vectors.jurisdiction.signed_request, public_key: vectors.second_admin.public_key } }

        const audit = await auditVoterAuthorizations(jurisdiction, vectors.voter_authorizations, root)

        expect(audit.authorizers.map(authorizer => authorizer.creator)).toEqual([false, true])
    })

    it("rejects authorizations that don't check out", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const jurisdiction_id = vectors.jurisdiction.id
        const authorizations = vectors.voter_authorizations
        const [first, second] = authorizations
        const withFirst = (authorization : VoterAuthorization) => [authorization, ...authorizations.slice(1)]
        const authorize = (body : unknown) => asAdmin(vectors, root, AUTHORIZE_VOTER_ACTION, JSON.stringify(body))

        const cases : Record<string, VoterAuthorization[]> = {
            "a voter listed twice": [...authorizations, first],
            "another voter's certificate": withFirst({ ...first, certificate: second.certificate }),
            "an admin's certificate": withFirst({ ...first, certificate: { ...first.certificate, cert_pem: vectors.admin.cert_pem } }),
            "a certificate listed for another role": withFirst({ ...first, certificate: { ...first.certificate, role: CertificateRole.registrar } }),
            "a certificate listed for another jurisdiction": withFirst({ ...first, certificate: { ...first.certificate, jurisdiction_id: OTHER_ID } }),
            "an authorization in another jurisdiction": withFirst({ ...first, authorization: await authorize({ jurisdiction_id: OTHER_ID, public_key: vectors.voters[0].public_key }) }),
            "an authorization of another key": withFirst({ ...first, authorization: await authorize({ jurisdiction_id, public_key: vectors.voters[1].public_key }) }),
            "an authorization signed by a voter": withFirst({ ...first, authorization: await asVoter(vectors, root, vectors.voters[0], AUTHORIZE_VOTER_ACTION, first.authorization.body) }),
            "an authorization altered after signing": withFirst({ ...first, authorization: { ...first.authorization, body: first.authorization.body.replace(jurisdiction_id, OTHER_ID) } }),
            "an authorization under another root's certificate": withFirst({ ...first, authorization: { ...first.authorization, cert_pem: vectors.other_root_admin_cert } }),
        }
        expect(await accepted(cases, list => auditVoterAuthorizations(vectors.jurisdiction, list, root))).toEqual([])

        // the errors say which authorization didn't check out
        await expect(auditVoterAuthorizations({ ...vectors.jurisdiction, id: OTHER_ID }, authorizations, root)).rejects.toThrow("voter authorization 1:")
        await expect(auditVoterAuthorizations(vectors.jurisdiction, [...authorizations, first], root)).rejects.toThrow("voter authorization 8:")
    })
})

describe("auditBlindSignatureRequests", () => {
    it("counts every voter's request", async () => {
        const vectors = loadVectors()

        const audit = await auditBlindSignatureRequests(vectors.election, vectors.blind_signature_requests, await loadRoot(vectors.root))

        expect(audit).toEqual({ counted: vectors.voters.length, authorizers: vectorAuthorizers(vectors), other_key: [] })
    })

    it("marks the key that signed the election's creation", async () => {
        const vectors = loadVectors()
        const election : Election = { ...vectors.election, signed_request: { ...vectors.election.signed_request, public_key: oneLine(vectors.second_admin.public_key) } }

        const audit = await auditBlindSignatureRequests(election, vectors.blind_signature_requests, await loadRoot(vectors.root))

        expect(audit.authorizers.map(authorizer => authorizer.creator)).toEqual([false, true])
    })

    it("counts each voter and each blinded message once", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const requests = vectors.blind_signature_requests
        const key_hash = await publicKeyHash(vectors.election.public_key)
        const ask = async (voter : number, blinded_message : string) : Promise<BlindSignatureRequest> => ({
            signed_request: await asVoter(vectors, root, vectors.voters[voter], REQUEST_BLIND_SIGNATURE_ACTION, JSON.stringify({ election_id: vectors.election.id, blinded_message, public_key_hash: key_hash })),
            authorization: requests[voter].authorization,
        })

        // the first voter asks again, for another message
        const again = await ask(0, randomMessage())
        const twice = await auditBlindSignatureRequests(vectors.election, [...requests, again], root)
        expect(twice.counted).toBe(vectors.voters.length)
        expect(twice.authorizers).toEqual(vectorAuthorizers(vectors))

        // the second voter asks for the first voter's message, instead of their own, so only the
        // requests that are counted count toward their admin's voters
        const copied = await ask(1, JSON.parse(requests[0].signed_request.body).blinded_message)
        const copy = await auditBlindSignatureRequests(vectors.election, [requests[0], copied, ...requests.slice(2)], root)
        expect(copy.counted).toBe(vectors.voters.length - 1)
        expect(copy.authorizers).toEqual(vectorAuthorizers(vectors, vectors.voters.length - 2))
    })

    it("sets aside requests that name another key", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const requests = vectors.blind_signature_requests
        // the first voter was given another key to blind their vote under
        const other_key : BlindSignatureRequest = {
            signed_request: await asVoter(vectors, root, vectors.voters[0], REQUEST_BLIND_SIGNATURE_ACTION, JSON.stringify({
                election_id: vectors.election.id,
                blinded_message: randomMessage(),
                public_key_hash: await publicKeyHash(vectors.admin.public_key),
            })),
            authorization: requests[0].authorization,
        }

        const audit = await auditBlindSignatureRequests(vectors.election, [other_key, ...requests.slice(1)], root)

        expect(audit.counted).toBe(vectors.voters.length - 1)
        expect(audit.authorizers).toEqual(vectorAuthorizers(vectors, vectors.voters.length - 2))
        expect(audit.other_key).toEqual([other_key])
    })

    it("rejects requests that don't check out", async () => {
        const vectors = loadVectors()
        const root = await loadRoot(vectors.root)
        const requests = vectors.blind_signature_requests
        const [first, second] = requests
        const body = JSON.parse(first.signed_request.body)
        const withFirst = (request : BlindSignatureRequest) => [request, ...requests.slice(1)]
        const ask = async (request_body : unknown) : Promise<BlindSignatureRequest> =>
            ({ ...first, signed_request: await asVoter(vectors, root, vectors.voters[0], REQUEST_BLIND_SIGNATURE_ACTION, JSON.stringify(request_body)) })

        const cases : Record<string, BlindSignatureRequest[]> = {
            "a request altered after signing": withFirst({ ...first, signed_request: { ...first.signed_request, body: JSON.stringify({ ...body, blinded_message: randomMessage() }) } }),
            "a request for another election": withFirst(await ask({ ...body, election_id: OTHER_ID })),
            "a body with another field": withFirst(await ask({ ...body, extra: 1 })),
            "a blinded message that isn't base64": withFirst(await ask({ ...body, blinded_message: "not base64!" })),
            "a request signed by the admin": withFirst({ ...first, signed_request: await asAdmin(vectors, root, REQUEST_BLIND_SIGNATURE_ACTION, first.signed_request.body) }),
            "a request by a voter in another jurisdiction": withFirst({ ...first, signed_request: await signAs(vectors.voters[0], { action: REQUEST_BLIND_SIGNATURE_ACTION, role: CertificateRole.voter, jurisdiction_id: OTHER_ID, body: first.signed_request.body, instance: root.instance }) }),
            "another voter's authorization": withFirst({ ...first, authorization: second.authorization }),
            "an authorization in another jurisdiction": withFirst({ ...first, authorization: await asAdmin(vectors, root, AUTHORIZE_VOTER_ACTION, JSON.stringify({ jurisdiction_id: OTHER_ID, public_key: vectors.voters[0].public_key })) }),
            "an authorization signed by a voter": withFirst({ ...first, authorization: await asVoter(vectors, root, vectors.voters[0], AUTHORIZE_VOTER_ACTION, first.authorization.body) }),
            "the voter's own request as the authorization": withFirst({ ...first, authorization: first.signed_request }),
        }
        expect(await accepted(cases, list => auditBlindSignatureRequests(vectors.election, list, root))).toEqual([])

        // the error says which request didn't check out
        await expect(auditBlindSignatureRequests(vectors.election, [...requests, { ...first, authorization: second.authorization }], root)).rejects.toThrow("blind signature request 8:")
    })
})
