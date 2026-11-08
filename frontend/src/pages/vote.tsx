import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert, Breadcrumb, Button, Form, Modal, Spinner } from "react-bootstrap";
import { User } from "@/models/user";
import { Candidate, Election, electionStatus, getElection } from "@/services/electionservice";
import { Ballot, voteCandidate } from "@/utils/ballot";
import { getUser, isVoterIn } from "@/utils/user";
import { castBallot, loadBallot, messageFor } from "@/utils/voting";

export default function VotePage() : React.JSX.Element {
    const {election_id} = useParams();
    const [user, setUser] = useState<User|null>(null);
    const [userLoaded, setUserLoaded] = useState(false);
    const [election, setElection] = useState<Election|null>(null);
    const [loading, setLoading] = useState(true);
    // the vote the voter saved: undefined until it has been checked for, and null if they haven't
    // started voting
    const [savedBallot, setSavedBallot] = useState<Ballot|null|undefined>(undefined);
    const [choice, setChoice] = useState("");
    const [confirming, setConfirming] = useState(false);
    // the step of casting in progress, or null when the vote isn't being cast
    const [step, setStep] = useState<string|null>(null);
    const [cast, setCast] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(maybe_user => {
            setUser(maybe_user)
            setUserLoaded(true)
        })

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

    const authorized = election != null && isVoterIn(user, election.jurisdiction_id)
    const status = election != null ? electionStatus(election, Date.now() / 1000) : null
    const open = status == "open"

    // check whether the voter has already started voting, so they finish that vote instead of
    // starting another
    useEffect(() => {
        if (user == null || election == null || !authorized || !open) {
            return
        }

        let cancelled = false

        loadBallot(user, election).then(ballot => {
            if (!cancelled) {
                setSavedBallot(ballot)
            }
        }).catch(error => {
            if (!cancelled) {
                setErrorMessage(messageFor(error))
            }
        })

        return () => { cancelled = true };
    }, [user, election, authorized, open]);

    const submit = function(chosen : string|null) {
        if (user == null || election == null) {
            return
        }

        setConfirming(false)
        setErrorMessage("")

        castBallot(user, election, chosen, setStep, setSavedBallot).then(() => {
            setStep(null)
            setCast(true)
        }).catch(error => {
            setStep(null)
            setErrorMessage(messageFor(error))
        })
    }

    const submitForm = function(event : React.FormEvent<HTMLFormElement>) {
        event.preventDefault()
        setConfirming(true)
    }

    const findCandidate = function(candidate_id : string|null) : Candidate|undefined {
        return election != null ? election.candidates.find(candidate => candidate.id == candidate_id) : undefined
    }

    const title = election != null ? election.title : "Election"
    const casting = step != null
    const votable = election != null && authorized && open && !cast
    const savedCandidate = election != null && savedBallot != null ? findCandidate(voteCandidate(savedBallot, election.id)) : undefined
    const chosenCandidate = findCandidate(choice)

    return (
        <div className="container">
            <Breadcrumb>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions" }}>
                    Jurisdictions
                </Breadcrumb.Item>
                {election != null && (
                    <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions/" + election.jurisdiction_id + "/elections" }}>
                        Elections
                    </Breadcrumb.Item>
                )}
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/elections/" + election_id }}>
                    {title}
                </Breadcrumb.Item>
                <Breadcrumb.Item active>
                    Vote
                </Breadcrumb.Item>
            </Breadcrumb>
            <h2 className="text-center">
                Vote: {title}
            </h2>
            {loading && (
                <p className="text-center">Loading...</p>
            )}
            {userLoaded && user == null && (
                <Alert variant="warning">
                    <Link to="/login">Log in</Link> to vote.
                </Alert>
            )}
            {election != null && user != null && !authorized && (
                <Alert variant="warning">
                    You aren&apos;t authorized to vote in this election&apos;s jurisdiction.
                </Alert>
            )}
            {election != null && authorized && !open && !cast && (
                <Alert variant="info">
                    {status == "upcoming"
                        ? "Voting opens " + new Date(election.time_open * 1000).toLocaleString() + "."
                        : "Voting closed " + new Date(election.time_close * 1000).toLocaleString() + "."}
                </Alert>
            )}
            {cast && (
                <Alert variant="success">
                    Your vote was cast. <Link to={"/elections/" + election_id}>Back to the election</Link>
                </Alert>
            )}
            {votable && savedBallot === undefined && errorMessage == "" && (
                <p className="text-center">Checking for a saved vote...</p>
            )}
            {votable && savedBallot != null && (
                <>
                    <p>
                        You chose <strong>{savedCandidate != null ? savedCandidate.name : "a candidate"}</strong>.
                        That choice is saved and can&apos;t be changed. Finish casting your vote to make sure it&apos;s recorded.
                    </p>
                    <Button variant="primary" onClick={() => submit(null)} disabled={casting}>
                        Finish casting my vote
                    </Button>
                </>
            )}
            {votable && savedBallot === null && election != null && (
                <Form onSubmit={submitForm}>
                    <fieldset disabled={casting}>
                        {election.candidates.map(candidate => (
                            <Form.Check
                                type="radio"
                                key={candidate.id}
                                id={"candidate-" + candidate.id}
                                name="candidate"
                                className="mb-3"
                                label={
                                    <>
                                        <div className="fw-bold">{candidate.name}</div>
                                        {candidate.description}
                                    </>
                                }
                                checked={choice == candidate.id}
                                onChange={() => setChoice(candidate.id)}
                            />
                        ))}
                        <Button variant="primary" type="submit" disabled={choice == ""}>
                            Cast vote
                        </Button>
                    </fieldset>
                </Form>
            )}
            {casting && (
                <p className="mt-3">
                    <Spinner as="span" animation="border" size="sm" className="me-2" />
                    {step}...
                </p>
            )}
            <Modal show={confirming} onHide={() => setConfirming(false)}>
                <Modal.Header closeButton>
                    <Modal.Title>Cast your vote?</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    You&apos;re voting for <strong>{chosenCandidate != null ? chosenCandidate.name : ""}</strong>.
                    Once you continue, your choice is saved and can&apos;t be changed.
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="secondary" onClick={() => setConfirming(false)}>
                        Go back
                    </Button>
                    <Button variant="primary" onClick={() => submit(choice)}>
                        Cast my vote
                    </Button>
                </Modal.Footer>
            </Modal>
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
