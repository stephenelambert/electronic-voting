package model

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"electronic-voting/util/hashtree"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InsertHashNodes inserts the nodes of the election's hash tree. Hashes are stored as base64.
func InsertHashNodes(ctx context.Context, tx pgx.Tx, electionID string, nodes []hashtree.Node) (err error) {
	// copying encodes values in binary, which needs the id parsed rather than as text
	electionUUID, err := uuid.Parse(electionID)
	if err != nil {
		err = fmt.Errorf("error parsing election id: %w", err)
		return
	}

	rows := make([][]any, len(nodes))
	for i, node := range nodes {
		rows[i] = []any{
			electionUUID,
			node.FirstLeaf,
			node.LeafCount,
			node.Counts,
			base64.StdEncoding.EncodeToString(node.Hash[:]),
		}
	}

	_, err = tx.CopyFrom(ctx,
		pgx.Identifier{"hashes"},
		[]string{"election_id", "first_leaf", "leaf_count", "counts", "hash_value"},
		pgx.CopyFromRows(rows))
	if err != nil {
		log.Printf("error inserting hash tree nodes: %v", err)
	}

	return
}

// FindHashNodes finds the nodes of the election's hash tree with the given IDs, by ID. IDs that
// aren't in the tree are left out.
func FindHashNodes(ctx context.Context, tx pgx.Tx, electionID string, ids []hashtree.NodeID) (nodes map[hashtree.NodeID]hashtree.Node, err error) {
	firstLeaves := make([]int64, len(ids))
	leafCounts := make([]int64, len(ids))
	for i, id := range ids {
		firstLeaves[i] = id.FirstLeaf
		leafCounts[i] = id.LeafCount
	}

	rows, err := tx.Query(ctx,
		`SELECT DISTINCT hashes.first_leaf, hashes.leaf_count, hashes.counts, hashes.hash_value
		FROM hashes
		INNER JOIN unnest($2::BIGINT[], $3::BIGINT[]) AS wanted(first_leaf, leaf_count)
			ON hashes.first_leaf = wanted.first_leaf
			AND hashes.leaf_count = wanted.leaf_count
		WHERE hashes.election_id = $1;`,
		electionID,
		firstLeaves,
		leafCounts)
	if err != nil {
		log.Printf("error querying for hash tree nodes: %v", err)
		return
	}

	defer rows.Close()

	nodes = make(map[hashtree.NodeID]hashtree.Node, len(ids))
	for rows.Next() {
		var node hashtree.Node
		var hashValue string

		if err = rows.Scan(&node.FirstLeaf, &node.LeafCount, &node.Counts, &hashValue); err != nil {
			log.Printf("error scanning for hash tree node: %v", err)
			return
		}

		var hash []byte
		hash, err = base64.StdEncoding.DecodeString(hashValue)
		if err == nil && len(hash) != len(node.Hash) {
			err = fmt.Errorf("hash is %d bytes", len(hash))
		}
		if err != nil {
			log.Printf("invalid hash for hash tree node %v: %v", node.NodeID, err)
			return
		}
		copy(node.Hash[:], hash)

		nodes[node.NodeID] = node
	}
	rows.Close()

	if err = rows.Err(); err != nil {
		log.Printf("error encountered while querying for hash tree nodes: %v", err)
		return
	}

	return
}
