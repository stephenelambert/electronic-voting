package hashtree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"

	"electronic-voting/util/votecounts"
)

var testCandidateIDs = []string{
	"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
	"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d",
	"3d6f5a1b-2c4e-4f8a-9b7c-0e1d2f3a4b5c",
}

// testLeaves returns count leaves in nonce order, with votes for the test candidates in turn
func testLeaves(count int) []Leaf {
	leaves := make([]Leaf, count)
	for i := range leaves {
		nonce := make([]byte, 32)
		nonce[0], nonce[1] = byte(i>>8), byte(i)
		candidateID := testCandidateIDs[i%len(testCandidateIDs)]

		leaves[i] = Leaf{
			Nonce:       nonce,
			Signature:   bytes.Repeat([]byte{byte(i)}, 256),
			Vote:        `{"version":1,"election_id":"a1b2c3d4-e5f6-4789-8abc-def012345678","candidate_id":"` + candidateID + `"}`,
			CandidateID: candidateID,
		}
	}

	return leaves
}

// byID indexes nodes by their IDs
func byID(nodes []Node) map[NodeID]Node {
	index := make(map[NodeID]Node, len(nodes))
	for _, node := range nodes {
		index[node.NodeID] = node
	}

	return index
}

// rootFromPath rebuilds the root of a tree of size votes from the leaf at position and the nodes on
// its audit path, the way clients check a proof: the path must have exactly the nodes AuditPath
// names, and each node's counts must be canonical and total the votes under it
func rootFromPath(leaf Leaf, position, size int64, path []Node) (root Node, err error) {
	if position < 0 || position >= size {
		err = errors.New("position is outside the tree")
		return
	}

	want := AuditPath(position, size)
	if len(path) != len(want) {
		err = fmt.Errorf("path has %d nodes, want %d", len(path), len(want))
		return
	}

	counts := votecounts.Counts{leaf.CandidateID: 1}
	node := Node{
		NodeID: NodeID{FirstLeaf: position, LeafCount: 1},
		Counts: votecounts.Encode(counts),
		Hash:   LeafHash(leaf),
	}
	for i, sibling := range path {
		if sibling.NodeID != want[i] {
			err = fmt.Errorf("path node %d is %v, want %v", i, sibling.NodeID, want[i])
			return
		}

		var siblingCounts votecounts.Counts
		if siblingCounts, err = votecounts.Decode(sibling.Counts); err != nil {
			return
		}
		if siblingCounts.Total() != uint64(sibling.LeafCount) {
			err = fmt.Errorf("path node %v counts %d votes", sibling.NodeID, siblingCounts.Total())
			return
		}

		left, right := node, sibling
		if sibling.FirstLeaf < node.FirstLeaf {
			left, right = sibling, node
		}

		counts = votecounts.Sum(counts, siblingCounts)
		node = Node{
			NodeID: NodeID{FirstLeaf: left.FirstLeaf, LeafCount: left.LeafCount + right.LeafCount},
			Counts: votecounts.Encode(counts),
			Hash:   NodeHash(left, right),
		}
	}

	root = node

	return
}

func TestSplit(t *testing.T) {
	cases := map[int64]int64{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
	for leafCount, want := range cases {
		if got := Split(leafCount); got != want {
			t.Errorf("Split(%d) is %d, want %d", leafCount, got, want)
		}
	}
}

// TestAuditPathMatchesReadmeExample checks the example in docs/design.md: a vote at position 5 of
// 16 is checked with the nodes (4,1), (6,2), (0,4) and (8,8)
func TestAuditPathMatchesReadmeExample(t *testing.T) {
	want := []NodeID{{4, 1}, {6, 2}, {0, 4}, {8, 8}}
	if got := AuditPath(5, 16); !slices.Equal(got, want) {
		t.Errorf("audit path is %v, want %v", got, want)
	}
}

func TestBuild(t *testing.T) {
	for count := 1; count <= 40; count++ {
		leaves := testLeaves(count)
		root, nodes := Build(leaves)

		if len(nodes) != 2*count-1 {
			t.Fatalf("%d votes built %d nodes, want %d", count, len(nodes), 2*count-1)
		}
		if nodes[len(nodes)-1] != root || root.NodeID != (NodeID{0, int64(count)}) {
			t.Fatalf("%d votes have root %v, which should cover every vote and be the last node", count, root.NodeID)
		}
		if len(byID(nodes)) != len(nodes) {
			t.Fatalf("%d votes built nodes with the same ID", count)
		}

		tally := votecounts.Counts{}
		for _, leaf := range leaves {
			tally[leaf.CandidateID]++
		}
		if root.Counts != votecounts.Encode(tally) {
			t.Errorf("%d votes have root counts %s, want %s", count, root.Counts, votecounts.Encode(tally))
		}

		for _, node := range nodes {
			counts, err := votecounts.Decode(node.Counts)
			if err != nil {
				t.Fatalf("node %v has invalid counts: %v", node.NodeID, err)
			}
			if counts.Total() != uint64(node.LeafCount) {
				t.Errorf("node %v counts %d votes", node.NodeID, counts.Total())
			}
		}
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	first, _ := Build(testLeaves(13))
	second, _ := Build(testLeaves(13))
	if first != second {
		t.Errorf("building the same votes twice gave different roots")
	}
}

func TestEmptyRoot(t *testing.T) {
	root, nodes := Build(nil)

	if len(nodes) != 0 {
		t.Errorf("a tree with no votes has %d nodes", len(nodes))
	}
	// SHA-256 of nothing
	if got := hex.EncodeToString(root.Hash[:]); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root hash is %s", got)
	}
	if root.Counts != "{}" || root.NodeID != (NodeID{0, 0}) {
		t.Errorf("empty root is %v with counts %s", root.NodeID, root.Counts)
	}
}

func TestEveryAuditPathRebuildsTheRoot(t *testing.T) {
	for count := 1; count <= 70; count++ {
		leaves := testLeaves(count)
		root, nodes := Build(leaves)
		index := byID(nodes)

		for position := range int64(count) {
			ids := AuditPath(position, int64(count))
			path := make([]Node, len(ids))
			for i, id := range ids {
				node, ok := index[id]
				if !ok {
					t.Fatalf("audit path for %d of %d names %v, which isn't in the tree", position, count, id)
				}
				path[i] = node
			}

			rebuilt, err := rootFromPath(leaves[position], position, int64(count), path)
			if err != nil {
				t.Fatalf("audit path for %d of %d was rejected: %v", position, count, err)
			}
			if rebuilt != root {
				t.Fatalf("audit path for %d of %d rebuilt a different root", position, count)
			}
		}
	}
}

func TestRootFromPathRejectsAlteredProofs(t *testing.T) {
	const position, size = 5, 16

	leaves := testLeaves(size)
	root, nodes := Build(leaves)
	index := byID(nodes)

	path := []Node{}
	for _, id := range AuditPath(position, size) {
		path = append(path, index[id])
	}

	// each alteration either fails to rebuild a root or rebuilds a different one
	alterations := map[string]func(path []Node) []Node{
		"moved vote": func(path []Node) []Node {
			// (0,4) has two votes for the first test candidate. Counting one of them for the
			// second keeps its total right
			path[2].Counts = votecounts.Encode(votecounts.Counts{testCandidateIDs[0]: 1, testCandidateIDs[1]: 2, testCandidateIDs[2]: 1})
			return path
		},
		"too many votes": func(path []Node) []Node {
			path[0].Counts = `{"` + testCandidateIDs[1] + `":2}`
			return path
		},
		"altered hash": func(path []Node) []Node {
			path[3].Hash[0] ^= 1
			return path
		},
		"swapped nodes": func(path []Node) []Node {
			path[2], path[3] = path[3], path[2]
			return path
		},
		"missing node": func(path []Node) []Node {
			return path[:3]
		},
		"extra node": func(path []Node) []Node {
			return append(path, path[3])
		},
		"non-canonical counts": func(path []Node) []Node {
			path[0].Counts = `{"` + testCandidateIDs[1] + `": 1}`
			return path
		},
	}
	for name, alter := range alterations {
		t.Run(name, func(t *testing.T) {
			rebuilt, err := rootFromPath(leaves[position], position, size, alter(slices.Clone(path)))
			if err == nil && rebuilt == root {
				t.Errorf("altered proof rebuilt the root")
			}
		})
	}

	t.Run("other position", func(t *testing.T) {
		rebuilt, err := rootFromPath(leaves[position], position+1, size, path)
		if err == nil && rebuilt == root {
			t.Errorf("proof for another position rebuilt the root")
		}
	})
	t.Run("other vote", func(t *testing.T) {
		rebuilt, err := rootFromPath(leaves[position+1], position, size, path)
		if err == nil && rebuilt == root {
			t.Errorf("proof rebuilt the root for a different vote")
		}
	})
}

func TestNodeHashLengthPrefixesCounts(t *testing.T) {
	left := Node{Counts: `{"a":1}`}
	right := Node{Counts: `{}`}
	// the same bytes, split between the children differently
	shiftedLeft := Node{Counts: `{"a":1}{`}
	shiftedRight := Node{Counts: `}`}

	if NodeHash(left, right) == NodeHash(shiftedLeft, shiftedRight) {
		t.Errorf("counts split differently between the children hashed the same")
	}
}

func TestNodeHashCoversEachChildsCounts(t *testing.T) {
	children := func(leftCounts, rightCounts string) (Node, Node) {
		return Node{Counts: leftCounts, Hash: sha256.Sum256([]byte("left"))}, Node{Counts: rightCounts, Hash: sha256.Sum256([]byte("right"))}
	}

	// both pairs total two votes for a and one for b, so only hashing each child's counts tells
	// them apart
	honestLeft, honestRight := children(`{"a":2}`, `{"b":1}`)
	movedLeft, movedRight := children(`{"a":1,"b":1}`, `{"a":1}`)

	if NodeHash(honestLeft, honestRight) == NodeHash(movedLeft, movedRight) {
		t.Errorf("moving a vote between the children didn't change the hash")
	}
}
