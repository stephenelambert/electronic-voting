import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert, Breadcrumb, Button, Card, ListGroup } from "react-bootstrap";
import CreationCheck from "@/components/creationcheck";
import ElectionAudit from "@/components/electionaudit";
import ElectionStatusBadge from "@/components/electionstatusbadge";
import ElectionVotes from "@/components/electionvotes";
import KeyFingerprint from "@/components/keyfingerprint";
import { User } from "@/models/user";
import { Election, electionStatus, getElection } from "@/services/electionservice";
import { getJurisdiction, Jurisdiction } from "@/services/jurisdictionservice";
import { getUser, isVoterIn } from "@/utils/user";

export default function ElectionPage() : React.JSX.Element {
    const {election_id} = useParams();
    const [election, setElection] = useState<Election|null>(null);
    const [jurisdiction, setJurisdiction] = useState<Jurisdiction|null>(null);
    const [user, setUser] = useState<User|null>(null);
    const [loading, setLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState("");

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(setUser)

        // no cleanup necessary
        return () => {};
    }, []);

    useEffect(() => {
        if (typeof election_id !== "string") {
            return
        }

        // ignore responses for an election that is no longer shown
        let cancelled = false

        setLoading(true)
        setElection(null)
        setErrorMessage("")

        getElection(election_id).then(resp => {
            if (cancelled) {
                return
            }
            setLoading(false)

            if (resp == null) {
                setErrorMessage("Error connecting to server to load election")
                return
            }
            if (resp.status_code == 404) {
                setErrorMessage("Election not found")
                return
            }
            if (resp.status_code != 200) {
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            setElection(resp.election)
        })

        return () => { cancelled = true };
    }, [election_id]);

    const jurisdictionId = election != null ? election.jurisdiction_id : null

    // load the election's jurisdiction for its name
    useEffect(() => {
        if (jurisdictionId == null) {
            return
        }

        getJurisdiction(jurisdictionId).then(resp => {
            if (resp != null && resp.status_code == 200) {
                setJurisdiction(resp.jurisdiction)
            }
        })

        // no cleanup necessary
        return () => {};
    }, [jurisdictionId]);

    const title = election != null ? election.title : "Election"

    return (
        <div className="container">
            <Breadcrumb>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions" }}>
                    Jurisdictions
                </Breadcrumb.Item>
                {jurisdictionId != null && (
                    <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions/" + jurisdictionId }}>
                        {jurisdiction != null ? jurisdiction.name : "Jurisdiction"}
                    </Breadcrumb.Item>
                )}
                {jurisdictionId != null && (
                    <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions/" + jurisdictionId + "/elections" }}>
                        Elections
                    </Breadcrumb.Item>
                )}
                <Breadcrumb.Item active>
                    {title}
                </Breadcrumb.Item>
            </Breadcrumb>
            <h2 className="text-center">
                {title}
            </h2>
            {loading && (
                <p className="text-center">Loading...</p>
            )}
            {election != null && (
                <>
                    <Card className="mb-3">
                        <Card.Body>
                            <div className="mb-2">
                                <ElectionStatusBadge time_open={election.time_open} time_close={election.time_close} />
                            </div>
                            {election.description != "" && (
                                // keep the line breaks entered in the description
                                <Card.Text style={{ whiteSpace: "pre-line" }}>{election.description}</Card.Text>
                            )}
                            <Card.Text>
                                Opens {new Date(election.time_open * 1000).toLocaleString()}
                                <br />
                                Closes {new Date(election.time_close * 1000).toLocaleString()}
                            </Card.Text>
                        </Card.Body>
                        <Card.Footer className="text-muted">
                            Created {new Date(election.created_timestamp * 1000).toLocaleString()}
                        </Card.Footer>
                    </Card>
                    {isVoterIn(user, election.jurisdiction_id) && (
                        // voters can only vote while the election is open
                        <div className="mb-3">
                            {electionStatus(election, Date.now() / 1000) == "open" ? (
                                <Link to={"/elections/" + election.id + "/vote"} className="btn btn-primary">
                                    Vote
                                </Link>
                            ) : (
                                <Button variant="primary" disabled>
                                    Vote
                                </Button>
                            )}
                        </div>
                    )}
                    <h4>Candidates</h4>
                    <ListGroup as="ol" numbered className="mb-3">
                        {election.candidates.map(candidate => (
                            <ListGroup.Item as="li" key={candidate.id} className="d-flex align-items-start">
                                <div className="ms-2">
                                    <div className="fw-bold">{candidate.name}</div>
                                    {candidate.description}
                                </div>
                            </ListGroup.Item>
                        ))}
                    </ListGroup>
                    <ElectionVotes election={election} user={user} />
                    <h4>Election Key</h4>
                    <p className="text-muted">
                        Votes in this election are signed with the key that has this fingerprint.
                    </p>
                    <KeyFingerprint public_key={election.public_key} variant="full" />
                    <h4 className="mt-3">Audit</h4>
                    <CreationCheck election={election} />
                    {electionStatus(election, Date.now() / 1000) == "closed" && (
                        // votes are only published once the election closes. keyed by election, so
                        // another election starts a new audit
                        <ElectionAudit key={election.id} election={election} />
                    )}
                </>
            )}
            <Alert
                variant="danger"
                className="mt-3"
                onClose={() => setErrorMessage("")}
                show={errorMessage != ""}>
                {errorMessage}
            </Alert>
        </div>
    );
}
