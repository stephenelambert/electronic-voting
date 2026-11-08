// Package hashtree builds the hash tree of an election's votes (see Hashes in docs/design.md): a
// Merkle tree shaped like RFC 9162's, whose nodes also count the votes for each candidate under
// them. Clients and auditors rebuild parts of the tree to check votes, so its hashes have to match
// theirs byte for byte.
package hashtree

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"slices"

	"electronic-voting/util/votecounts"
)

const (
	// leafPrefix and nodePrefix start what is hashed for leaves and internal nodes, as in RFC 9162,
	// so a leaf's hash can't be passed off as an internal node's
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// Leaf is a vote, as the tree hashes and counts it
type Leaf struct {
	// Nonce and Signature are raw bytes rather than their stored text. Both have fixed lengths (the
	// nonce's, and the election key's), so the vote can go last in the leaf's hash without a length
	// prefix.
	Nonce     []byte
	Signature []byte
	// Vote is the vote JSON, exactly as signed
	Vote string
	// CandidateID is the candidate the vote is for, which the leaf counts one vote for
	CandidateID string
}

// NodeID identifies a node by the votes under it: LeafCount votes, starting at position FirstLeaf
// in nonce order. The root covers every vote, and a leaf is a node with a LeafCount of 1.
type NodeID struct {
	FirstLeaf int64
	LeafCount int64
}

// Node is a node of the tree
type Node struct {
	NodeID
	// Counts are the votes for each candidate ID under the node, encoded by votecounts.Encode,
	// exactly as they are hashed
	Counts string
	Hash   [sha256.Size]byte
}

// LeafHash returns the hash of a leaf: SHA-256 of 0x00, the nonce, the signature and the vote
func LeafHash(leaf Leaf) [sha256.Size]byte {
	data := make([]byte, 0, 1+len(leaf.Nonce)+len(leaf.Signature)+len(leaf.Vote))
	data = append(data, leafPrefix)
	data = append(data, leaf.Nonce...)
	data = append(data, leaf.Signature...)
	data = append(data, leaf.Vote...)

	return sha256.Sum256(data)
}

// NodeHash returns the hash of the internal node with the given children: SHA-256 of 0x01, each
// child's counts prefixed with their length as a 4-byte big-endian integer, then each child's hash.
// Each child's counts are hashed separately, since hashing only their total would let the server
// undercount without any voter's proof failing. Counts vary in length, so the prefixes keep the
// same bytes from being split into the two children's counts in more than one way.
func NodeHash(left, right Node) [sha256.Size]byte {
	data := make([]byte, 0, 1+4+len(left.Counts)+4+len(right.Counts)+2*sha256.Size)
	data = append(data, nodePrefix)
	data = binary.BigEndian.AppendUint32(data, uint32(len(left.Counts)))
	data = append(data, left.Counts...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(right.Counts)))
	data = append(data, right.Counts...)
	data = append(data, left.Hash[:]...)
	data = append(data, right.Hash[:]...)

	return sha256.Sum256(data)
}

// Split returns how many of a node's leafCount votes, which must be at least 2, are under its left
// child: the largest power of two smaller than leafCount, as in RFC 9162
func Split(leafCount int64) int64 {
	return 1 << (bits.Len64(uint64(leafCount-1)) - 1)
}

// EmptyRoot returns the root of a tree with no votes, which has no nodes: SHA-256 of nothing, as in
// RFC 9162, with no votes counted
func EmptyRoot() Node {
	return Node{
		Counts: votecounts.Encode(votecounts.Counts{}),
		Hash:   sha256.Sum256(nil),
	}
}

// Build builds the tree over leaves, which must be in nonce order, and returns its root and every
// node in it, with the root last. A tree with no leaves has no nodes, and its root is EmptyRoot.
func Build(leaves []Leaf) (root Node, nodes []Node) {
	if len(leaves) == 0 {
		return EmptyRoot(), nil
	}

	nodes = make([]Node, 0, 2*len(leaves)-1)
	root, _ = build(leaves, 0, &nodes)

	return
}

// build appends the nodes of the subtree over leaves to nodes, with the subtree's root last, and
// returns its root and counts. first is the position of the subtree's first leaf.
func build(leaves []Leaf, first int64, nodes *[]Node) (node Node, counts votecounts.Counts) {
	leafCount := int64(len(leaves))

	if leafCount == 1 {
		counts = votecounts.Counts{leaves[0].CandidateID: 1}
		node = Node{
			NodeID: NodeID{FirstLeaf: first, LeafCount: 1},
			Counts: votecounts.Encode(counts),
			Hash:   LeafHash(leaves[0]),
		}
	} else {
		k := Split(leafCount)
		left, leftCounts := build(leaves[:k], first, nodes)
		right, rightCounts := build(leaves[k:], first+k, nodes)

		counts = votecounts.Sum(leftCounts, rightCounts)
		node = Node{
			NodeID: NodeID{FirstLeaf: first, LeafCount: leafCount},
			Counts: votecounts.Encode(counts),
			Hash:   NodeHash(left, right),
		}
	}

	*nodes = append(*nodes, node)

	return
}

// AuditPath returns the IDs of the nodes needed to rebuild the root of a tree of size votes from
// the leaf at position, which must be less than size: the sibling of each node on the path from the
// leaf up to the root, bottom-up
func AuditPath(position, size int64) []NodeID {
	path := []NodeID{}

	// walk down from the root to the leaf, then reverse
	node := NodeID{FirstLeaf: 0, LeafCount: size}
	for node.LeafCount > 1 {
		k := Split(node.LeafCount)
		left := NodeID{FirstLeaf: node.FirstLeaf, LeafCount: k}
		right := NodeID{FirstLeaf: node.FirstLeaf + k, LeafCount: node.LeafCount - k}

		if position < right.FirstLeaf {
			path = append(path, right)
			node = left
		} else {
			path = append(path, left)
			node = right
		}
	}
	slices.Reverse(path)

	return path
}
