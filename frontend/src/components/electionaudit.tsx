import React, { useState } from "react";
import { Alert, Button, ListGroup, Spinner } from "react-bootstrap";
import AuthorizerList from "@/components/authorizerlist";
import KeyFingerprint from "@/components/keyfingerprint";
import { Election } from "@/services/electionservice";
import { auditElection, AuditedElection, encodeResultsBody, ResultsError } from "@/utils/results";

// Finding is one thing auditing an election found, to show the user
interface Finding {
    variant: "success" | "info" | "danger";
    message: React.ReactNode;
}

// count says how many of something there are, like "3 votes" or "1 vote"
function count(n : number, singular : string, plural : string) : string {
    return n.toLocaleString() + " " + (n == 1 ? singular : plural)
}

// findings lists what auditing an election found in its records, once each one checks out: whether
// the published results match the votes, how many votes the requests for blind signatures allow and
// which admins' keys authorized their voters, and whether there are more votes than that
function findings(audited : AuditedElection) : Finding[] {
    const { votes, results, request_count, requests } = audited
    const list : Finding[] = []

    list.push({
        variant: "success",
        message: "Every published vote checks out (" + count(votes.vote_count, "vote", "votes") + "): each is a valid vote in this election with a signature from its key, and they're in nonce order.",
    })

    if (results == null) {
        list.push({ variant: "info", message: "The results haven't been published yet, so there are none to check the votes against." })
    } else if (encodeResultsBody(results.body) !== encodeResultsBody(votes)) {
        list.push({ variant: "danger", message: "The published results don't match the votes: their count, tally or hash tree root is different. Report this to the election's administrators." })
    } else {
        list.push({
            variant: "success",
            message: (
                <>
                    The published results match the votes: the same count, tally and hash tree root. A global
                    admin signed them, whose key has fingerprint <KeyFingerprint public_key={results.signer_public_key} />.
                </>
            ),
        })
    }

    list.push({
        variant: "success",
        message: "Every published request for a blind signature checks out (" + count(request_count, "request", "requests") + "): each was signed by a voter that a global admin authorized in this jurisdiction. Counting each voter and each blinded message once, they allow up to " + count(requests.counted, "vote", "votes") + ".",
    })

    // the server's host holds the root key, so it could issue itself a global admin certificate and
    // authorize voters of its own, which only its key's fingerprint would show
    if (requests.authorizers.length > 0) {
        list.push({
            variant: "info",
            message: (
                <>
                    The voters who made the counted requests were authorized
                    by {count(requests.authorizers.length, "global admin key", "global admin keys")}, listed
                    by fingerprint. Check that each is one of the real global admins&apos; keys: one that
                    isn&apos;t could be a key the server issued itself, to authorize extra voters.
                    <AuthorizerList authorizers={requests.authorizers} noun="election" />
                </>
            ),
        })
    }

    if (requests.other_key.length > 0) {
        list.push({
            variant: "danger",
            message: count(requests.other_key.length, "request names", "requests name") + " a key other than the election's, so they aren't counted. Their voters signed them, so the server gave those voters a different key, which could let it recognize their votes. Report this to the election's administrators.",
        })
    }

    // the server only signs a vote for a voter's request, so a valid vote without one means the
    // election's key signed votes that no authorized voter asked for
    const counts = "votes (" + votes.vote_count.toLocaleString() + ") than requests from distinct authorized voters (" + requests.counted.toLocaleString() + ")"
    if (votes.vote_count <= requests.counted) {
        list.push({ variant: "success", message: "There are no more " + counts + "." })
    } else {
        list.push({
            variant: "danger",
            message: "There are more " + counts + ", so votes were signed that no authorized voter asked for. Report this to the election's administrators.",
        })
    }

    return list
}

interface ElectionAuditProps {
    election: Election;
}

// ElectionAudit lets anyone audit a closed election: it downloads every published vote and request
// for a blind signature, checks each one and the published results, and shows what it found
export default function ElectionAudit({ election } : ElectionAuditProps) : React.JSX.Element {
    // the step of the audit in progress, or null when the election isn't being audited
    const [step, setStep] = useState<string|null>(null);
    const [audited, setAudited] = useState<AuditedElection|null>(null);
    const [errorMessage, setErrorMessage] = useState("");

    const audit = function() {
        setAudited(null)
        setErrorMessage("")

        auditElection(election, setStep).then(setAudited).catch(error => {
            if (error instanceof ResultsError) {
                setErrorMessage(error.message)
            } else {
                console.log("error auditing the election", error)
                setErrorMessage("Error auditing the election")
            }
        }).then(() => {
            setStep(null)
        })
    }

    return (
        <>
            <p className="text-muted">
                Auditing downloads every published vote and request for a blind signature in this
                election, checks each one, and checks that there are no more votes than requests from
                distinct authorized voters.
            </p>
            <Button variant="outline-primary" className="mb-3" onClick={audit} disabled={step != null}>
                Audit every vote and signature request
            </Button>
            {step != null && (
                <p>
                    <Spinner as="span" animation="border" size="sm" className="me-2" />
                    {step}...
                </p>
            )}
            {audited != null && (
                <ListGroup className="mb-3">
                    {findings(audited).map((finding, i) => (
                        <ListGroup.Item key={i} variant={finding.variant}>
                            {finding.message}
                        </ListGroup.Item>
                    ))}
                </ListGroup>
            )}
            {errorMessage != "" && (
                <Alert variant="danger">{errorMessage}</Alert>
            )}
        </>
    );
}
