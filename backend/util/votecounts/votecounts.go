// Package votecounts encodes vote counts the way published tallies store them and the hash tree
// hashes them: one JSON object with a field for each candidate ID that has votes, keys sorted, with
// no whitespace and no zero counts, like {"<id1>":1,"<id2>":4}.
package votecounts

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Counts holds the number of votes for each candidate ID. A candidate with no votes can be missing
// or zero.
type Counts map[string]uint64

// Total returns the number of votes counted
func (c Counts) Total() (total uint64) {
	for _, count := range c {
		total += count
	}

	return
}

// Sum returns the counts of a and b added together, leaving both unchanged
func Sum(a, b Counts) Counts {
	sum := make(Counts, len(a)+len(b))
	for candidateID, count := range a {
		sum[candidateID] += count
	}
	for candidateID, count := range b {
		sum[candidateID] += count
	}

	return sum
}

// Encode returns the one encoding of counts, which leaves out candidates with no votes
func Encode(counts Counts) string {
	nonzero := make(map[string]uint64, len(counts))
	for candidateID, count := range counts {
		if count != 0 {
			nonzero[candidateID] = count
		}
	}

	// json.Marshal sorts map keys and adds no whitespace, and can't fail for a map of strings to
	// numbers
	encoded, _ := json.Marshal(nonzero)

	return string(encoded)
}

// Decode decodes counts, which must be exactly what Encode produces. Anything else is rejected, so a
// hash of encoded counts can only stand for one set of counts, however the JSON is parsed.
func Decode(encoded string) (counts Counts, err error) {
	if err = json.Unmarshal([]byte(encoded), &counts); err != nil {
		err = fmt.Errorf("counts aren't a JSON object of counts: %w", err)
		return
	}
	if counts == nil {
		err = errors.New("counts are null")
		return
	}

	// whitespace, unsorted or repeated keys, zero counts and escapes don't survive the round trip
	if Encode(counts) != encoded {
		err = errors.New("counts aren't in canonical form")
		return
	}

	return
}
