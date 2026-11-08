import React, { useEffect, useState } from "react";
import { Alert, Button, Modal, Spinner } from "react-bootstrap";
import TallyTable from "@/components/tallytable";
import { Election } from "@/services/electionservice";
import { publishResults } from "@/services/voteservice";
import { decodeCounts } from "@/utils/hashtree";
import { auditPublishedVotes, encodeResultsBody, ResultsBody, ResultsError, tallyEntries } from "@/utils/results";

interface PublishResultsModalProps {
    election: Election;
    show: boolean;
    onHide: () => void;
    // called once the results are published
    onPublished: () => void;
}

// PublishResultsModal lets an admin check every published vote in an election and rebuild its hash
// tree, then sign the tally and the tree's root to publish them. The server only accepts results that
// match its own tree, so publishing also shows that its tree is built from the votes it published.
export default function PublishResultsModal({ election, show, onHide, onPublished } : PublishResultsModalProps) : React.JSX.Element {
    // the step of checking the votes in progress, or null when they aren't being checked
    const [step, setStep] = useState<string|null>(null);
    // the results the published votes give, once every vote has been checked
    const [results, setResults] = useState<ResultsBody|null>(null);
    const [submitting, setSubmitting] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");

    // check the votes each time the modal opens, since they're what the admin signs for
    useEffect(() => {
        if (!show) {
            return
        }

        let cancelled = false

        auditPublishedVotes(election, current => {
            if (!cancelled) {
                setStep(current)
            }
        }).then(audited => {
            if (!cancelled) {
                setResults(audited)
            }
        }).catch(error => {
            if (cancelled) {
                return
            }
            if (error instanceof ResultsError) {
                setErrorMessage(error.message)
            } else {
                console.log("error checking the published votes", error)
                setErrorMessage("Error checking the published votes")
            }
        }).then(() => {
            if (!cancelled) {
                setStep(null)
            }
        })

        return () => { cancelled = true };
    }, [show, election]);

    // clear everything once the modal has closed, so it opens fresh next time
    const reset = function() {
        setStep(null)
        setResults(null)
        setSubmitting(false)
        setErrorMessage("")
    }

    const submit = function() {
        if (results == null) {
            return
        }

        setSubmitting(true)
        setErrorMessage("")

        publishResults(election.id, encodeResultsBody(results)).then(resp => {
            setSubmitting(false)

            if (resp == null) {
                setErrorMessage("Error connecting to server to publish the results")
                return
            }
            if (resp.status_code == 400) {
                setErrorMessage("The server's hash tree doesn't match these results, so they weren't published. The server may be counting different votes than the ones it published.")
                return
            }
            if (resp.status_code == 403) {
                setErrorMessage("The election's votes aren't final yet")
                return
            }
            if (resp.status_code == 409) {
                setErrorMessage("Different results were already published for this election")
                return
            }
            if (resp.status_code == 401) {
                setErrorMessage("You aren't authorized to publish results")
                return
            }
            if (resp.status_code != 201 && resp.status_code != 200) {
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            onPublished()
        })
    }

    return (
        <Modal show={show} onHide={onHide} onExited={reset}>
            <Modal.Header closeButton>
                <Modal.Title>Publish Results</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {step != null && (
                    <p>
                        <Spinner as="span" animation="border" size="sm" className="me-2" />
                        {step}...
                    </p>
                )}
                {results != null && (
                    <>
                        <p>
                            Every published vote checks out: each is a valid vote in this election with a
                            signature from its key, and they&apos;re in nonce order. The{" "}
                            {results.vote_count.toLocaleString()} {results.vote_count == 1 ? "vote gives" : "votes give"} this tally:
                        </p>
                        <TallyTable election={election} tally={tallyEntries(election, decodeCounts(results.tally))} />
                        <p className="mt-3">
                            The root of their hash tree is <code className="text-break">{results.root_hash}</code>
                        </p>
                        <p className="mb-0">
                            Signing publishes this tally and root. Voters check their votes against the
                            root, and the server only accepts it if its own tree has the same root.
                        </p>
                    </>
                )}
                <Alert
                    variant="danger"
                    className="mt-3 mb-0"
                    onClose={() => setErrorMessage("")}
                    show={errorMessage != ""}
                    dismissible>
                    {errorMessage}
                </Alert>
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" disabled={submitting} onClick={onHide}>
                    Cancel
                </Button>
                <Button variant="primary" disabled={results == null || submitting} onClick={submit}>
                    {submitting ? "Publishing..." : "Sign and publish"}
                </Button>
            </Modal.Footer>
        </Modal>
    );
}
