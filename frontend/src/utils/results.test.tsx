import { describe, expect, it } from "vitest"
import { CertificateRole } from "../models/certificate"
import { PUBLISH_RESULTS_ACTION, PublishedVote, VoteProof } from "../services/voteservice"
import { SignedRequest } from "./auth"
import { arrayBufferToBase64 } from "./base64"
import { EMPTY_ROOT_HASH, encodeCounts } from "./hashtree"
import { checkElectionPublicKey } from "./keys"
import { auditVotes, checkProof, encodeResultsBody, ResultsBody, ResultsError, tallyEntries, verifyResults } from "./results"
import { loadRoot, Root } from "./root"
import { accepted, loadVectors, signAs, VECTOR_CANDIDATE_IDS, vectorElection, Vectors } from "./testvectors"

// vectorResults returns the results that publish the vectors' votes
function vectorResults(vectors : Vectors) : ResultsBody {
    return JSON.parse(vectors.results)
}

// vectorProof returns the API's proof for the vote with the nonce, and the vote checked
function vectorProof(vectors : Vectors, nonce : string, index = 0) : { vote: PublishedVote, proof: VoteProof } {
    const found = vectors.proofs.filter(proof => proof.vote.nonce == nonce)[index]
    if (found == null) {
        throw new Error("vectors have no proof for " + nonce)
    }

    return structuredClone(found)
}

// signResults signs a request as the vectors' global admin, the way their client does
async function signResults(vectors : Vectors, root : Root, body : string, request_timestamp? : string, action = PUBLISH_RESULTS_ACTION) : Promise<SignedRequest> {
    return await signAs(vectors.admin, { action, role: CertificateRole.global_admin, jurisdiction_id: null, body, instance: root.instance, request_timestamp })
}

describe("encodeResultsBody", () => {
    it("matches the API's encoding", () => {
        const body = encodeResultsBody({
            election_id: "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
            vote_count: 3,
            root_hash: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            tally: `{"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d":2,"a1b2c3d4-e5f6-4789-8abc-def012345678":1}`,
        })

        // the same as TestResultsBodyIsExact in the API's tests
        expect(body).toBe(`{"election_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","vote_count":3,"root_hash":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","tally":"{\\"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d\\":2,\\"a1b2c3d4-e5f6-4789-8abc-def012345678\\":1}"}`)
    })
})

describe("auditVotes", () => {
    it("works out the results the API built", async () => {
        const vectors = loadVectors()
        const election_key = await checkElectionPublicKey(vectors.public_key)

        const body = await auditVotes(vectorElection(vectors), election_key, vectors.votes)

        expect(encodeResultsBody(body)).toBe(vectors.results)
    })

    it("works out the results of an election with no votes", async () => {
        const vectors = loadVectors()
        const election_key = await checkElectionPublicKey(vectors.public_key)

        const body = await auditVotes(vectorElection(vectors), election_key, [])

        expect(body).toEqual({ election_id: vectors.election_id, vote_count: 0, root_hash: EMPTY_ROOT_HASH, tally: "{}" })
    })

    it("rejects invalid or unordered votes", async () => {
        const vectors = loadVectors()
        const election = vectorElection(vectors)
        const election_key = await checkElectionPublicKey(vectors.public_key)

        const alterations : Record<string, (votes : PublishedVote[]) => PublishedVote[]> = {
            "out of order": votes => [votes[1], votes[0], ...votes.slice(2)],
            "repeated nonce": votes => [votes[0], ...votes],
            // the fifth vote's nonce is a0 repeated, so it has letters to change
            "uppercase nonce": votes => [...votes.slice(0, 4), { ...votes[4], nonce: votes[4].nonce.toUpperCase() }, ...votes.slice(5)],
            "another vote's signature": votes => [{ ...votes[0], signature: votes[1].signature }, ...votes.slice(1)],
            "whitespace in a vote": votes => [{ ...votes[0], vote: votes[0].vote.replace(",", ", ") }, ...votes.slice(1)],
            "vote in another election": votes => [{ ...votes[0], vote: votes[0].vote.replace(vectors.election_id, VECTOR_CANDIDATE_IDS[0]) }, ...votes.slice(1)],
        }
        // only a ResultsError counts as rejecting the votes, since its message is shown to the admin
        expect(await accepted(alterations, async alter => {
            const error : unknown = await auditVotes(election, election_key, alter(structuredClone(vectors.votes))).then(() => null, error => error)
            if (error instanceof ResultsError) {
                throw error
            }
        })).toEqual([])
    })
})

describe("checkProof", () => {
    it("finds each published vote counted", async () => {
        const vectors = loadVectors()
        const election_key = await checkElectionPublicKey(vectors.public_key)

        for (const vote of vectors.votes) {
            const { proof } = vectorProof(vectors, vote.nonce)
            expect(await checkProof(vectorElection(vectors), election_key, vectorResults(vectors), vote.nonce, vote.vote, proof)).toBe("counted")
        }
    })

    it("finds votes that aren't in the tree left out", async () => {
        const vectors = loadVectors()
        const election_key = await checkElectionPublicKey(vectors.public_key)

        // before the first vote, between the first two, and after the last
        for (const byte of ["10", "30", "f0"]) {
            const { vote, proof } = vectorProof(vectors, byte.repeat(32))
            expect(await checkProof(vectorElection(vectors), election_key, vectorResults(vectors), vote.nonce, vote.vote, proof), byte).toBe("left_out")
        }
    })

    it("finds a different vote published with a vote's nonce", async () => {
        const vectors = loadVectors()
        const election_key = await checkElectionPublicKey(vectors.public_key)

        // the vectors' second proof for the fourth vote's nonce is for a different vote
        const { vote, proof } = vectorProof(vectors, "80".repeat(32), 1)
        expect(vote.vote).not.toBe(vectors.votes[3].vote)

        expect(await checkProof(vectorElection(vectors), election_key, vectorResults(vectors), vote.nonce, vote.vote, proof)).toBe("replaced")
    })

    it("finds a vote left out of an election with no votes", async () => {
        const vectors = loadVectors()
        const election_key = await checkElectionPublicKey(vectors.public_key)
        const results : ResultsBody = { election_id: vectors.election_id, vote_count: 0, root_hash: EMPTY_ROOT_HASH, tally: "{}" }
        const vote = vectors.votes[0]

        expect(await checkProof(vectorElection(vectors), election_key, results, vote.nonce, vote.vote, { leaves: [] })).toBe("left_out")
        // an election with votes always has some in the proof
        await expect(checkProof(vectorElection(vectors), election_key, vectorResults(vectors), vote.nonce, vote.vote, { leaves: [] })).rejects.toThrow()
    })

    it("rejects proofs that don't show where a vote is", async () => {
        const vectors = loadVectors()
        const election = vectorElection(vectors)
        const election_key = await checkElectionPublicKey(vectors.public_key)
        const results = vectorResults(vectors)

        // the vote between the first two published votes, whose proof has both of them
        const { vote, proof } = vectorProof(vectors, "30".repeat(32))
        const [first, second] = proof.leaves
        const third = vectorProof(vectors, vectors.votes[2].nonce).proof.leaves[0]

        const alterations : Record<string, VoteProof> = {
            "only the vote before it": { leaves: [first] },
            "only the vote after it": { leaves: [second] },
            "votes that aren't next to each other": { leaves: [first, third] },
            "votes in the wrong order": { leaves: [second, first] },
            "the same vote twice": { leaves: [first, first] },
            "an altered path": { leaves: [first, { ...second, path: second.path.map((node, i) => i == 0 ? { ...node, counts: encodeCounts(new Map([[VECTOR_CANDIDATE_IDS[2], 1]])) } : node) }] },
            "an altered vote": { leaves: [first, { ...second, vote: vectors.votes[2].vote }] },
            "a vote that isn't in the tree": { leaves: [first, { ...second, nonce: "40".repeat(31) + "41" }] },
        }
        expect(await accepted(alterations, altered => checkProof(election, election_key, results, vote.nonce, vote.vote, altered))).toEqual([])

        // a proof that matches other results
        const other_results : ResultsBody = { ...results, root_hash: vectorResults(vectors).root_hash.replace(/^./, c => c == "A" ? "B" : "A") }
        await expect(checkProof(election, election_key, other_results, vote.nonce, vote.vote, proof)).rejects.toThrow()

        // a published vote's proof alongside another vote
        const counted = vectorProof(vectors, vectors.votes[0].nonce)
        await expect(checkProof(election, election_key, results, counted.vote.nonce, counted.vote.vote, { leaves: [...counted.proof.leaves, second] })).rejects.toThrow()
    })
})

describe("verifyResults", () => {
    it("accepts the results a global admin published", async () => {
        const vectors = loadVectors()
        const signed_request = vectors.published_results.signed_request

        const verified = await verifyResults(vectorElection(vectors), vectors.published_results, await loadRoot(vectors.root))

        expect(verified.body).toEqual(vectorResults(vectors))
        expect(verified.tally.get(VECTOR_CANDIDATE_IDS[0])).toBe(3)
        expect(verified.signer_public_key).toBe(vectors.admin.public_key)
        expect(verified.signed_timestamp).toBe(Number(signed_request.request_timestamp))
    })

    it("doesn't use the server's timestamp, which isn't signed", async () => {
        const vectors = loadVectors()
        const signed_request = await signResults(vectors, await loadRoot(vectors.root), vectors.results)

        const verified = await verifyResults(vectorElection(vectors), { signed_request, created_timestamp: 1700000000 }, await loadRoot(vectors.root))

        expect(verified.signed_timestamp).toBe(Number(signed_request.request_timestamp))
    })

    it("rejects altered or invalid results", async () => {
        const vectors = loadVectors()
        const election = vectorElection(vectors)
        const results = vectorResults(vectors)
        const root = await loadRoot(vectors.root)
        const other_root = await loadRoot(vectors.other_root)
        const action = PUBLISH_RESULTS_ACTION

        const signed = vectors.published_results.signed_request
        const cases : Record<string, SignedRequest> = {
            "altered after signing": { ...signed, body: encodeResultsBody({ ...results, vote_count: 8 }) },
            "a timestamp altered after signing": { ...signed, request_timestamp: (Number(signed.request_timestamp) - 60000).toString() },
            "an instance altered after signing": { ...signed, instance: arrayBufferToBase64(new Uint8Array(32).fill(1).buffer) },
            "a role altered after signing": { ...signed, role: CertificateRole.voter },
            "a jurisdiction added after signing": { ...signed, jurisdiction_id: vectors.jurisdiction.id },
            "a timestamp that isn't a number": await signResults(vectors, root, vectors.results, "yesterday"),
            "for another action": await signResults(vectors, root, vectors.results, undefined, "recovery_record.create"),
            "for another election": await signResults(vectors, root, encodeResultsBody({ ...results, election_id: VECTOR_CANDIDATE_IDS[0] })),
            "whitespace": await signResults(vectors, root, vectors.results.replace(",", ", ")),
            "an extra field": await signResults(vectors, root, vectors.results.replace(/}$/, `,"extra":1}`)),
            "a vote count as text": await signResults(vectors, root, vectors.results.replace(`"vote_count":7`, `"vote_count":"7"`)),
            "a tally missing a vote": await signResults(vectors, root, encodeResultsBody({ ...results, vote_count: 8 })),
            "a short root hash": await signResults(vectors, root, encodeResultsBody({ ...results, root_hash: arrayBufferToBase64(new Uint8Array(31).buffer) })),
            // who signed them
            "signed by a voter": await signAs(vectors.voters[0], { action, role: CertificateRole.voter, jurisdiction_id: vectors.jurisdiction.id, body: vectors.results, instance: root.instance }),
            "signed without a certificate": { ...signed, cert_pem: null },
            "signed under another root's certificate": { ...signed, cert_pem: vectors.other_root_admin_cert },
            "signed for another instance": await signAs({ ...vectors.admin, cert_pem: vectors.other_root_admin_cert }, { action, role: CertificateRole.global_admin, jurisdiction_id: null, body: vectors.results, instance: other_root.instance }),
        }
        expect(await accepted(cases, signed_request => verifyResults(election, { signed_request, created_timestamp: 0 }, root))).toEqual([])
    })
})

describe("tallyEntries", () => {
    it("lists the ballot in order, then other candidates", () => {
        const vectors = loadVectors()
        const election = vectorElection(vectors)
        const tally = new Map([
            [VECTOR_CANDIDATE_IDS[1], 3],
            // candidates who aren't on the ballot
            ["f1d2c3b4-a5e6-4789-8abc-def012345678", 2],
            ["a1b2c3d4-e5f6-4789-8abc-def012345678", 1],
        ])

        expect(tallyEntries(election, tally)).toEqual([
            { candidate_id: VECTOR_CANDIDATE_IDS[0], votes: 0 },
            { candidate_id: VECTOR_CANDIDATE_IDS[1], votes: 3 },
            { candidate_id: VECTOR_CANDIDATE_IDS[2], votes: 0 },
            { candidate_id: "a1b2c3d4-e5f6-4789-8abc-def012345678", votes: 1 },
            { candidate_id: "f1d2c3b4-a5e6-4789-8abc-def012345678", votes: 2 },
        ])
    })
})
