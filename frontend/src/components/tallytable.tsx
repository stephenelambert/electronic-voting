import React from "react";
import { Table } from "react-bootstrap";
import { Election } from "@/services/electionservice";
import { TallyEntry } from "@/services/voteservice";

interface TallyTableProps {
    election: Election;
    tally: TallyEntry[];
}

// TallyTable shows how many votes each candidate in a tally has
export default function TallyTable({ election, tally } : TallyTableProps) : React.JSX.Element {
    // valid votes can name a candidate who isn't on the ballot, and are counted under that ID
    const candidateName = function(candidate_id : string) : string {
        const candidate = election.candidates.find(candidate => candidate.id == candidate_id)
        return candidate != null ? candidate.name : "Not on the ballot (" + candidate_id + ")"
    }

    return (
        <Table striped bordered size="sm" className="mb-1">
            <thead>
                <tr>
                    <th>Candidate</th>
                    <th>Votes</th>
                </tr>
            </thead>
            <tbody>
                {tally.map(entry => (
                    <tr key={entry.candidate_id}>
                        <td>{candidateName(entry.candidate_id)}</td>
                        <td>{entry.votes.toLocaleString()}</td>
                    </tr>
                ))}
            </tbody>
        </Table>
    );
}
