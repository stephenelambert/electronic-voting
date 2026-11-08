package votecounts

import (
	"maps"
	"testing"
)

const (
	firstID  = "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"
	secondID = "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d"
)

func TestEncodeSortsKeysAndDropsZeros(t *testing.T) {
	encoded := Encode(Counts{secondID: 4, firstID: 1, "a6f1c1d2-5b7e-4c1a-9e8f-2d3c4b5a6978": 0})

	want := `{"` + firstID + `":1,"` + secondID + `":4}`
	if encoded != want {
		t.Errorf("encoded counts are %s, want %s", encoded, want)
	}
}

func TestEncodeNoVotes(t *testing.T) {
	if encoded := Encode(Counts{}); encoded != "{}" {
		t.Errorf("encoded no votes as %s, want {}", encoded)
	}
}

func TestDecodeReversesEncode(t *testing.T) {
	counts := Counts{firstID: 7, secondID: 1 << 40}

	decoded, err := Decode(Encode(counts))
	if err != nil {
		t.Fatalf("error decoding counts: %v", err)
	}
	if !maps.Equal(decoded, counts) {
		t.Errorf("decoded counts are %v, want %v", decoded, counts)
	}
}

func TestDecodeRejectsOtherEncodings(t *testing.T) {
	cases := []string{
		"",
		"null",
		"[]",
		// whitespace
		`{"` + firstID + `": 1}`,
		// keys out of order
		`{"` + secondID + `":4,"` + firstID + `":1}`,
		// a zero count
		`{"` + firstID + `":0}`,
		// a repeated key
		`{"` + firstID + `":1,"` + firstID + `":1}`,
		// counts that aren't whole, non-negative numbers
		`{"` + firstID + `":1.0}`,
		`{"` + firstID + `":-1}`,
		`{"` + firstID + `":"1"}`,
		// an escaped key
		`{"\u0030b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a":1}`,
		// more than one object
		`{"` + firstID + `":1}{"` + secondID + `":4}`,
	}
	for _, encoded := range cases {
		if _, err := Decode(encoded); err == nil {
			t.Errorf("%s was decoded as counts", encoded)
		}
	}
}

func TestTotal(t *testing.T) {
	if total := (Counts{firstID: 3, secondID: 4}).Total(); total != 7 {
		t.Errorf("total is %d, want 7", total)
	}
}

func TestSum(t *testing.T) {
	a := Counts{firstID: 3}
	b := Counts{firstID: 1, secondID: 4}

	sum := Sum(a, b)

	if want := (Counts{firstID: 4, secondID: 4}); !maps.Equal(sum, want) {
		t.Errorf("sum is %v, want %v", sum, want)
	}
	if !maps.Equal(a, Counts{firstID: 3}) || !maps.Equal(b, Counts{firstID: 1, secondID: 4}) {
		t.Errorf("summing changed the counts being added")
	}
}
