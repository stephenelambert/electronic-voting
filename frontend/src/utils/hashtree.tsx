import { arrayBufferToBase64, base64ToArrayBuffer } from "./base64"

// The hash tree of an election's votes (see Hashes in docs/design.md): a Merkle tree shaped like
// RFC 9162's, whose nodes also count the votes for each candidate under them. This mirrors the
// API's util/hashtree package, and has to hash exactly what it does.

// LEAF_PREFIX and NODE_PREFIX start what is hashed for leaves and internal nodes, as in RFC 9162, so
// a leaf's hash can't be passed off as an internal node's
const LEAF_PREFIX = 0x00
const NODE_PREFIX = 0x01

// HASH_BYTES is the length of a node's hash (SHA-256)
const HASH_BYTES = 32

// EMPTY_ROOT_HASH is the root hash of a tree with no votes, which has no nodes: SHA-256 of nothing,
// as in RFC 9162
export const EMPTY_ROOT_HASH = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

// NONCE_PATTERN matches a vote's nonce: 32 bytes as lowercase hex, the only form the API stores, so
// nonces compare as strings in the same order as their bytes
const NONCE_PATTERN = /^[0-9a-f]{64}$/

// CANDIDATE_ID_PATTERN matches a candidate ID in canonical form (a lowercase, hyphenated UUID), the
// only form votes can name candidates in
const CANDIDATE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

// Counts holds the number of votes for each candidate ID
export type Counts = Map<string, number>

// encodeCounts returns the one encoding of counts, which the tree hashes: a JSON object with a field
// for each candidate ID that has votes, keys sorted, with no whitespace and no zero counts
export function encodeCounts(counts : Counts) : string {
    const candidate_ids : string[] = Array.from(counts.keys())
        .filter(candidate_id => counts.get(candidate_id) != 0)
        .sort()

    return "{" + candidate_ids.map(candidate_id => JSON.stringify(candidate_id) + ":" + counts.get(candidate_id)).join(",") + "}"
}

// decodeCounts decodes counts, which must be exactly what encodeCounts produces, with every key a
// candidate ID and every count a whole number small enough to add exactly. Anything else throws, so
// a hash of encoded counts can only stand for one set of counts, however the JSON is parsed.
export function decodeCounts(encoded : string) : Counts {
    const parsed : unknown = JSON.parse(encoded)
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("counts aren't a JSON object")
    }

    const fields = parsed as Record<string, unknown>
    const counts : Counts = new Map()
    for (const candidate_id of Object.keys(fields)) {
        const count : unknown = fields[candidate_id]
        if (!CANDIDATE_ID_PATTERN.test(candidate_id)) {
            throw new Error("counts have a key that isn't a candidate id")
        }
        if (typeof count !== "number" || !Number.isSafeInteger(count) || count <= 0) {
            throw new Error("counts have a count that isn't a positive whole number")
        }
        counts.set(candidate_id, count)
    }

    // whitespace, unsorted or repeated keys and other ways of writing numbers don't survive the
    // round trip
    if (encodeCounts(counts) !== encoded) {
        throw new Error("counts aren't in canonical form")
    }

    return counts
}

// addCounts returns the counts of a and b added together. It throws if a sum is too large to add
// exactly.
export function addCounts(a : Counts, b : Counts) : Counts {
    const sum : Counts = new Map(a)
    for (const [candidate_id, count] of b) {
        const total : number = (sum.get(candidate_id) ?? 0) + count
        if (!Number.isSafeInteger(total)) {
            throw new Error("too many votes to count exactly")
        }
        sum.set(candidate_id, total)
    }

    return sum
}

// countsTotal returns the number of votes counted. It throws if the total is too large to add
// exactly.
export function countsTotal(counts : Counts) : number {
    let total = 0
    for (const count of counts.values()) {
        total += count
        if (!Number.isSafeInteger(total)) {
            throw new Error("too many votes to count exactly")
        }
    }

    return total
}

// TreeLeaf is a vote as the tree hashes and counts it: its nonce (lowercase hex), its signature
// (base64), the vote JSON exactly as signed, and the ID of the candidate it's for
export interface TreeLeaf {
    nonce: string;
    signature: string;
    vote: string;
    candidate_id: string;
}

// NodeID identifies a node by the votes under it: leaf_count votes, starting at position first_leaf
// in nonce order. The root covers every vote, and a leaf is a node with a leaf_count of 1.
export interface NodeID {
    first_leaf: number;
    leaf_count: number;
}

// TreeNode is a node of the tree, as the API sends it: the votes for each candidate under it,
// exactly as hashed, and its hash (base64)
export interface TreeNode extends NodeID {
    counts: string;
    hash: string;
}

// isNonce reports whether nonce is a vote's nonce: 32 bytes as lowercase hex
export function isNonce(nonce : string) : boolean {
    return NONCE_PATTERN.test(nonce)
}

// nonceBytes decodes a nonce, which must be lowercase hex. A nonce written any other way could hash
// the same as one that compares differently, which would let a proof misplace a vote.
function nonceBytes(nonce : string) : Uint8Array {
    if (!isNonce(nonce)) {
        throw new Error("nonce isn't 32 bytes of lowercase hex")
    }

    const bytes = new Uint8Array(nonce.length / 2)
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(nonce.substring(2 * i, 2 * i + 2), 16)
    }
    return bytes
}

// bytesToBase64 encodes exactly the bytes in view, which may be part of a larger buffer
function bytesToBase64(bytes : Uint8Array) : string {
    return arrayBufferToBase64(bytes.slice().buffer)
}

// hashBytes decodes a hash, which must be exactly 32 bytes in canonical base64. Hashes have a fixed
// length, so they can go into a node's hash without a length prefix.
export function hashBytes(hash : string) : Uint8Array {
    const bytes = new Uint8Array(base64ToArrayBuffer(hash))
    if (bytes.length != HASH_BYTES || bytesToBase64(bytes) !== hash) {
        throw new Error("hash isn't a base64 sha-256 hash")
    }

    return bytes
}

async function sha256(data : Uint8Array) : Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data))
}

// leafHash returns the hash (base64) of a leaf: SHA-256 of 0x00, the nonce, the signature and the
// vote. The nonce and signature have fixed lengths, so the vote can go last without a length prefix.
export async function leafHash(leaf : TreeLeaf) : Promise<string> {
    const nonce : Uint8Array = nonceBytes(leaf.nonce)
    const signature = new Uint8Array(base64ToArrayBuffer(leaf.signature))
    const vote : Uint8Array = new TextEncoder().encode(leaf.vote)

    const data = new Uint8Array(1 + nonce.length + signature.length + vote.length)
    data[0] = LEAF_PREFIX
    data.set(nonce, 1)
    data.set(signature, 1 + nonce.length)
    data.set(vote, 1 + nonce.length + signature.length)

    return bytesToBase64(await sha256(data))
}

// nodeHash returns the hash (base64) of the internal node with the given children: SHA-256 of 0x01,
// each child's counts prefixed with their length as a 4-byte big-endian integer, then each child's
// hash. Each child's counts are hashed separately, since hashing only their total would let the
// server undercount without any voter's proof failing.
export async function nodeHash(left : TreeNode, right : TreeNode) : Promise<string> {
    const encoder = new TextEncoder()
    const left_counts : Uint8Array = encoder.encode(left.counts)
    const right_counts : Uint8Array = encoder.encode(right.counts)

    const data = new Uint8Array(1 + 4 + left_counts.length + 4 + right_counts.length + 2 * HASH_BYTES)
    const view = new DataView(data.buffer)
    let offset = 0

    data[offset] = NODE_PREFIX
    offset += 1
    // DataView writes big-endian unless told otherwise
    view.setUint32(offset, left_counts.length)
    offset += 4
    data.set(left_counts, offset)
    offset += left_counts.length
    view.setUint32(offset, right_counts.length)
    offset += 4
    data.set(right_counts, offset)
    offset += right_counts.length
    data.set(hashBytes(left.hash), offset)
    offset += HASH_BYTES
    data.set(hashBytes(right.hash), offset)

    return bytesToBase64(await sha256(data))
}

// split returns how many of a node's leaf_count votes, which must be at least 2, are under its left
// child: the largest power of two smaller than leaf_count, as in RFC 9162
export function split(leaf_count : number) : number {
    let k = 1
    while (k * 2 < leaf_count) {
        k *= 2
    }

    return k
}

// auditPath returns the IDs of the nodes needed to rebuild the root of a tree of size votes from the
// leaf at position, which must be less than size: the sibling of each node on the path from the leaf
// up to the root, bottom-up
export function auditPath(position : number, size : number) : NodeID[] {
    const path : NodeID[] = []

    // walk down from the root to the leaf, then reverse
    let node : NodeID = { first_leaf: 0, leaf_count: size }
    while (node.leaf_count > 1) {
        const k : number = split(node.leaf_count)
        const left : NodeID = { first_leaf: node.first_leaf, leaf_count: k }
        const right : NodeID = { first_leaf: node.first_leaf + k, leaf_count: node.leaf_count - k }

        if (position < right.first_leaf) {
            path.push(right)
            node = left
        } else {
            path.push(left)
            node = right
        }
    }

    return path.reverse()
}

// leafNode returns the leaf node for a vote at position
async function leafNode(leaf : TreeLeaf, position : number) : Promise<TreeNode> {
    return {
        first_leaf: position,
        leaf_count: 1,
        counts: encodeCounts(new Map([[leaf.candidate_id, 1]])),
        hash: await leafHash(leaf),
    }
}

// parentNode returns the internal node with the given children, whose counts add up to counts
async function parentNode(left : TreeNode, right : TreeNode, counts : Counts) : Promise<TreeNode> {
    return {
        first_leaf: left.first_leaf,
        leaf_count: left.leaf_count + right.leaf_count,
        counts: encodeCounts(counts),
        hash: await nodeHash(left, right),
    }
}

// buildSubtree appends the nodes of the subtree over leaf_count leaves, starting at position first,
// to nodes, with the subtree's root last, and returns its root and counts
async function buildSubtree(leaves : TreeLeaf[], first : number, leaf_count : number, nodes : TreeNode[]) : Promise<[TreeNode, Counts]> {
    let node : TreeNode
    let counts : Counts

    if (leaf_count == 1) {
        node = await leafNode(leaves[first], first)
        counts = new Map([[leaves[first].candidate_id, 1]])
    } else {
        const k : number = split(leaf_count)
        const [left, left_counts] = await buildSubtree(leaves, first, k, nodes)
        const [right, right_counts] = await buildSubtree(leaves, first + k, leaf_count - k, nodes)

        counts = addCounts(left_counts, right_counts)
        node = await parentNode(left, right, counts)
    }

    nodes.push(node)
    return [node, counts]
}

// Tree is a whole hash tree: its root, and every node in it, with the root last
export interface Tree {
    root: TreeNode;
    nodes: TreeNode[];
}

// buildTree builds the tree over leaves, which must be in nonce order. A tree with no leaves has no
// nodes, and its root's hash is EMPTY_ROOT_HASH, with no votes counted.
export async function buildTree(leaves : TreeLeaf[]) : Promise<Tree> {
    if (leaves.length == 0) {
        return {
            root: { first_leaf: 0, leaf_count: 0, counts: encodeCounts(new Map()), hash: EMPTY_ROOT_HASH },
            nodes: [],
        }
    }

    const nodes : TreeNode[] = []
    const [root] = await buildSubtree(leaves, 0, leaves.length, nodes)

    return { root, nodes }
}

// rootFromPath rebuilds the root of a tree of size votes from the leaf at position and its path from
// the API: the sibling of each node on the way from the leaf up to the root. It throws unless the
// path has exactly the nodes a tree of that size has there, each counting the votes under it.
export async function rootFromPath(leaf : TreeLeaf, position : number, size : number, path : TreeNode[]) : Promise<TreeNode> {
    if (!Number.isSafeInteger(size) || !Number.isSafeInteger(position) || position < 0 || position >= size) {
        throw new Error("position isn't in the tree")
    }

    const expected : NodeID[] = auditPath(position, size)
    if (path.length != expected.length) {
        throw new Error("path has " + path.length + " nodes instead of " + expected.length)
    }

    let node : TreeNode = await leafNode(leaf, position)
    let counts : Counts = decodeCounts(node.counts)
    for (let i = 0; i < path.length; i++) {
        const sibling : TreeNode = path[i]
        if (sibling.first_leaf !== expected[i].first_leaf || sibling.leaf_count !== expected[i].leaf_count) {
            throw new Error("path has the wrong nodes")
        }

        // each node has to count exactly the votes under it, so a server can't give one part of
        // the tree extra votes and another fewer
        const sibling_counts : Counts = decodeCounts(sibling.counts)
        if (countsTotal(sibling_counts) !== sibling.leaf_count) {
            throw new Error("a node on the path doesn't count the votes under it")
        }

        const [left, right] = sibling.first_leaf < node.first_leaf ? [sibling, node] : [node, sibling]
        counts = addCounts(counts, sibling_counts)
        node = await parentNode(left, right, counts)
    }

    return node
}
