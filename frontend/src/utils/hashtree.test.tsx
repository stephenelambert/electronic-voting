import { describe, expect, it } from "vitest"
import { arrayBufferToBase64 } from "./base64"
import { canonicalVoteCandidate } from "./ballot"
import { auditPath, buildTree, decodeCounts, EMPTY_ROOT_HASH, encodeCounts, NodeID, rootFromPath, split, TreeLeaf, TreeNode } from "./hashtree"
import { loadVectors, VECTOR_CANDIDATE_IDS, Vectors } from "./testvectors"

const FIRST_ID = "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"
const SECOND_ID = "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d"

// vectorLeaf returns a published vote as a tree leaf
function vectorLeaf(vectors : Vectors, vote : { nonce: string, vote: string, signature: string }) : TreeLeaf {
    const candidate_id = canonicalVoteCandidate(vote.vote, vectors.election_id)
    if (candidate_id == null) {
        throw new Error("vectors have an invalid vote")
    }

    return { nonce: vote.nonce, signature: vote.signature, vote: vote.vote, candidate_id }
}

// randomLeaves returns count leaves in nonce order, with random nonces and signatures
function randomLeaves(count : number) : TreeLeaf[] {
    const toHex = (bytes : Uint8Array) => Array.from(bytes).map(byte => ("0" + byte.toString(16)).slice(-2)).join("")

    const nonces : string[] = []
    for (let i = 0; i < count; i++) {
        nonces.push(toHex(crypto.getRandomValues(new Uint8Array(32))))
    }
    nonces.sort()

    return nonces.map((nonce, i) => ({
        nonce,
        signature: arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(256)).buffer),
        vote: "vote " + i,
        candidate_id: VECTOR_CANDIDATE_IDS[i % VECTOR_CANDIDATE_IDS.length],
    }))
}

// idKey returns a key for a node's ID, for finding nodes by ID
function idKey(id : NodeID) : string {
    return id.first_leaf + "," + id.leaf_count
}

describe("encodeCounts", () => {
    it("sorts keys and drops zeros", () => {
        const counts = new Map([[SECOND_ID, 4], [FIRST_ID, 1], ["a6f1c1d2-5b7e-4c1a-9e8f-2d3c4b5a6978", 0]])
        expect(encodeCounts(counts)).toBe(`{"` + FIRST_ID + `":1,"` + SECOND_ID + `":4}`)
    })

    it("encodes no votes as {}", () => {
        expect(encodeCounts(new Map())).toBe("{}")
    })
})

describe("decodeCounts", () => {
    it("reverses encodeCounts", () => {
        const counts = new Map([[FIRST_ID, 7], [SECOND_ID, 2 ** 40]])
        expect(decodeCounts(encodeCounts(counts))).toEqual(counts)
    })

    it("rejects other encodings", () => {
        const cases = [
            "",
            "null",
            "[]",
            // whitespace
            `{"` + FIRST_ID + `": 1}`,
            // keys out of order
            `{"` + SECOND_ID + `":4,"` + FIRST_ID + `":1}`,
            // a zero count
            `{"` + FIRST_ID + `":0}`,
            // a repeated key
            `{"` + FIRST_ID + `":1,"` + FIRST_ID + `":1}`,
            // counts that aren't whole, positive numbers
            `{"` + FIRST_ID + `":1.0}`,
            `{"` + FIRST_ID + `":-1}`,
            `{"` + FIRST_ID + `":"1"}`,
            // an escaped key
            `{"\\u0030b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a":1}`,
            // a key that isn't a candidate ID
            `{"candidate":1}`,
            // a count too large to add exactly
            `{"` + FIRST_ID + `":9007199254740992}`,
            // more than one object
            `{"` + FIRST_ID + `":1}{"` + SECOND_ID + `":4}`,
        ]
        for (const encoded of cases) {
            expect(() => decodeCounts(encoded), encoded).toThrow()
        }
    })
})

describe("split", () => {
    it("returns the largest power of two smaller than the number of votes", () => {
        const cases : [number, number][] = [[2, 1], [3, 2], [4, 2], [5, 4], [7, 4], [8, 4], [9, 8], [16, 8], [17, 16]]
        for (const [leaf_count, want] of cases) {
            expect(split(leaf_count), "split(" + leaf_count + ")").toBe(want)
        }
    })
})

describe("auditPath", () => {
    it("matches the example in docs/design.md", () => {
        expect(auditPath(5, 16)).toEqual([
            { first_leaf: 4, leaf_count: 1 },
            { first_leaf: 6, leaf_count: 2 },
            { first_leaf: 0, leaf_count: 4 },
            { first_leaf: 8, leaf_count: 8 },
        ])
    })
})

describe("buildTree", () => {
    it("builds the same root as the API", async () => {
        const vectors = loadVectors()
        const results = JSON.parse(vectors.results)

        const { root } = await buildTree(vectors.votes.map(vote => vectorLeaf(vectors, vote)))

        expect(root.hash).toBe(results.root_hash)
        expect(root.counts).toBe(results.tally)
        expect(root.leaf_count).toBe(results.vote_count)
    })

    it("builds the nodes in the API's proofs", async () => {
        const vectors = loadVectors()
        const { nodes } = await buildTree(vectors.votes.map(vote => vectorLeaf(vectors, vote)))
        const built = new Map(nodes.map(node => [idKey(node), node]))

        for (const { proof } of vectors.proofs) {
            for (const leaf of proof.leaves) {
                for (const node of leaf.path) {
                    expect(built.get(idKey(node))).toEqual(node)
                }
            }
        }
    })

    it("gives a tree with no votes the hash of nothing as its root", async () => {
        const nothing : string = arrayBufferToBase64(await crypto.subtle.digest("SHA-256", new Uint8Array()))
        expect(EMPTY_ROOT_HASH).toBe(nothing)

        const { root, nodes } = await buildTree([])
        expect(root).toEqual({ first_leaf: 0, leaf_count: 0, counts: "{}", hash: nothing })
        expect(nodes).toEqual([])
    })

    it("rebuilds its root from every audit path", async () => {
        for (let count = 1; count <= 33; count++) {
            const leaves = randomLeaves(count)
            const { root, nodes } = await buildTree(leaves)
            expect(nodes.length).toBe(2 * count - 1)
            expect(nodes[nodes.length - 1]).toEqual(root)

            const built = new Map(nodes.map(node => [idKey(node), node]))
            for (let position = 0; position < count; position++) {
                const path : TreeNode[] = auditPath(position, count).map(id => {
                    const node = built.get(idKey(id))
                    if (node == null) {
                        throw new Error("audit path names a node that isn't in the tree")
                    }
                    return node
                })

                expect(await rootFromPath(leaves[position], position, count, path)).toEqual(root)
            }
        }
    })
})

describe("rootFromPath", () => {
    it("rebuilds the root from the API's proofs", async () => {
        const vectors = loadVectors()
        const results = JSON.parse(vectors.results)

        for (const { proof } of vectors.proofs) {
            for (const leaf of proof.leaves) {
                const root = await rootFromPath(vectorLeaf(vectors, leaf), leaf.position, results.vote_count, leaf.path)
                expect(root.hash).toBe(results.root_hash)
                expect(root.counts).toBe(results.tally)
            }
        }
    })

    it("rejects altered paths", async () => {
        const vectors = loadVectors()
        const results = JSON.parse(vectors.results)
        // the vote at position 3, whose path is (2,1), (0,2), (4,3)
        const { proof } = vectors.proofs[3]
        const [published] = proof.leaves
        const leaf = vectorLeaf(vectors, published)
        expect(published.position).toBe(3)

        const alterations : Record<string, (path : TreeNode[]) => TreeNode[]> = {
            // (4,3) has a vote for each candidate. Counting the second candidate's for the first
            // instead keeps its total right
            "moved vote": path => {
                path[2].counts = encodeCounts(new Map([[VECTOR_CANDIDATE_IDS[0], 2], [VECTOR_CANDIDATE_IDS[2], 1]]))
                return path
            },
            "too many votes": path => {
                path[0].counts = encodeCounts(new Map([[VECTOR_CANDIDATE_IDS[2], 2]]))
                return path
            },
            "altered hash": path => {
                const node = path[2]
                node.hash = (node.hash[0] == "A" ? "B" : "A") + node.hash.slice(1)
                return path
            },
            "swapped nodes": path => [path[0], path[2], path[1]],
            "missing node": path => path.slice(0, 2),
            "extra node": path => [...path, path[2]],
            "non-canonical counts": path => {
                path[0].counts = path[0].counts.replace(":", ": ")
                return path
            },
            "id as text": path => {
                (path[0] as unknown as { first_leaf: string }).first_leaf = "2"
                return path
            },
        }
        // each alteration either fails to rebuild a root or rebuilds a different one
        const accepted : string[] = []
        for (const name of Object.keys(alterations)) {
            const path : TreeNode[] = alterations[name](published.path.map(node => ({ ...node })))
            const rebuilt : TreeNode|null = await rootFromPath(leaf, 3, results.vote_count, path).catch(() => null)
            if (rebuilt != null && rebuilt.hash == results.root_hash && rebuilt.counts == results.tally) {
                accepted.push(name)
            }
        }
        expect(accepted).toEqual([])

        await expect(rootFromPath(leaf, 4, results.vote_count, published.path)).rejects.toThrow()
        await expect(rootFromPath(leaf, 7, results.vote_count, published.path)).rejects.toThrow()
        const other = await rootFromPath(vectorLeaf(vectors, vectors.votes[4]), 3, results.vote_count, published.path)
        expect(other.hash).not.toBe(results.root_hash)
    })
})
