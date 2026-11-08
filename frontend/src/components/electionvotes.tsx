import React, { useEffect, useState } from "react";
import { Alert, Button, Spinner } from "react-bootstrap";
import KeyFingerprint from "@/components/keyfingerprint";
import PublishResultsModal from "@/components/publishresultsmodal";
import TallyTable from "@/components/tallytable";
import { User } from "@/models/user";
import { Election } from "@/services/electionservice";
import { getPublishedVotes, getRecoveryRecord, getResults, getVoteProof, getVoteSummary, publishedVotesEndpoint, VoteSummary } from "@/services/voteservice";
import { checkElectionKey } from "@/utils/audit";
import { Ballot, verifyVoteSignature } from "@/utils/ballot";
import { auditVotes, checkProof, encodeResultsBody, ProofResult, ResultsBody, ResultsError, tallyEntries, VerifiedResults, verifyResults } from "@/utils/results";
import { getRoot } from "@/utils/root";
import { isGlobalAdmin } from "@/utils/user";
import { messageFor, openRecoveryRecord, VoteError } from "@/utils/voting";

// SUMMARY_REFRESH_MS is how often the summary is refreshed until every vote is published
const SUMMARY_REFRESH_MS = 30 * 1000

// CheckResult is what checking the user's vote found, to show them
interface CheckResult {
    variant: "success" | "info" | "warning" | "danger";
    message: string;
    // offer_download is set when the user can check their vote against every published vote instead
    offer_download?: boolean;
}

// checkVote checks the user's vote. Once the election's results are published, it checks the proof
// for the vote from the election's hash tree against them, unless download_votes is set. Otherwise,
// it looks for the vote among all the published votes, which are only published once the election
// has closed.
async function checkVote(user : User, election : Election, results : VerifiedResults|null, download_votes : boolean, onStep : (step : string) => void) : Promise<CheckResult> {
    onStep("Checking for your vote")
    const record_resp = await getRecoveryRecord(election.id)
    if (record_resp == null) {
        throw new VoteError("Error connecting to server to check for your vote")
    }
    if (record_resp.status_code == 404) {
        return { variant: "info", message: "You haven't voted in this election." }
    }
    if (record_resp.status_code != 200 || record_resp.signed_request == null) {
        throw new VoteError("Unknown server error (status " + record_resp.status_code + ")")
    }
    const ballot = await openRecoveryRecord(user, election, record_resp.signed_request)

    let election_key : CryptoKey
    try {
        election_key = await checkElectionKey(election, await getRoot())
    } catch (error) {
        console.log("election key check failed", error)
        throw new VoteError("The election's key couldn't be confirmed, so the published votes can't be checked. Try again, and if it keeps happening, contact the election's administrators.")
    }

    if (results != null && !download_votes) {
        return await checkVoteProof(election, election_key, results, ballot, onStep)
    }
    return await findPublishedVote(election, election_key, results, ballot, onStep)
}

// checkVoteProof checks the proof for the user's vote from the election's hash tree against its
// published results. It only downloads the proof, but asking for it tells the server which vote is
// the user's.
async function checkVoteProof(election : Election, election_key : CryptoKey, results : VerifiedResults, ballot : Ballot, onStep : (step : string) => void) : Promise<CheckResult> {
    onStep("Checking your vote against the published results")
    const proof_resp = await getVoteProof(election.id, ballot.nonce)
    // once the results are published, an honest server has a proof for every nonce, and refusing one
    // is how a server could hide that it left a vote out, so this isn't shown as a passing error
    if (proof_resp == null || proof_resp.status_code != 200 || proof_resp.proof == null) {
        const problem = proof_resp == null ? "Couldn't connect to the server to fetch the proof for your vote" : "The server didn't send a proof for your vote (status " + proof_resp.status_code + ")"
        return {
            variant: "warning",
            message: problem + ", so it can't be checked against the published results. You can try again later, or check it against every published vote instead, which downloads all of them. If this keeps happening, report it to the election's administrators, along with your vote's nonce: " + ballot.nonce,
            offer_download: true,
        }
    }

    let result : ProofResult
    try {
        result = await checkProof(election, election_key, results.body, ballot.nonce, ballot.vote, proof_resp.proof)
    } catch (error) {
        console.log("the proof for the vote is invalid", error)
        return {
            variant: "danger",
            message: "The server's proof for your vote doesn't match the published results. Report this to the election's administrators, along with your vote's nonce: " + ballot.nonce,
        }
    }

    if (result == "replaced") {
        return {
            variant: "danger",
            message: "A different vote, or one without a valid signature, is counted in the published results with your vote's nonce. Report this to the election's administrators, along with your vote's nonce: " + ballot.nonce,
        }
    }
    if (result == "left_out") {
        return {
            variant: "danger",
            message: "Your vote isn't counted in the published results: their hash tree shows no vote with your vote's nonce. If you finished casting it, report this to the election's administrators, along with your vote's nonce: " + ballot.nonce,
        }
    }

    return { variant: "success", message: "Your vote is counted in the published results, with a valid signature." }
}

// findPublishedVote looks for the user's vote among the published votes. It downloads every vote,
// so the server doesn't learn which one is the user's. With published results, it first checks the
// votes the way an auditor would, and that they rebuild the results' hash tree, so finding the vote
// among them shows it's counted in the results.
async function findPublishedVote(election : Election, election_key : CryptoKey, results : VerifiedResults|null, ballot : Ballot, onStep : (step : string) => void) : Promise<CheckResult> {
    onStep("Downloading the published votes")
    const published_resp = await getPublishedVotes(election.id)
    if (published_resp == null) {
        throw new VoteError("Error connecting to server to fetch the published votes")
    }
    if (published_resp.status_code != 200) {
        throw new VoteError("Unknown server error (status " + published_resp.status_code + ")")
    }

    if (results != null) {
        onStep("Checking " + published_resp.votes.length.toLocaleString() + " votes against the published results")
        let audited : ResultsBody
        try {
            audited = await auditVotes(election, election_key, published_resp.votes)
        } catch (error) {
            if (!(error instanceof ResultsError)) {
                throw error
            }
            return { variant: "danger", message: error.message + " Report this to the election's administrators." }
        }
        if (encodeResultsBody(audited) !== encodeResultsBody(results.body)) {
            return { variant: "danger", message: "The published votes don't match the published results. Report this to the election's administrators." }
        }
    }

    const published_vote = published_resp.votes.find(vote => vote.nonce == ballot.nonce)
    if (published_vote == null) {
        return {
            variant: "danger",
            message: "Your vote isn't among the published votes. If you finished casting it, report this to the election's administrators, along with your vote's nonce: " + ballot.nonce,
        }
    }
    if (published_vote.vote != ballot.vote || !await verifyVoteSignature(election_key, published_vote.nonce, published_vote.vote, published_vote.signature)) {
        return {
            variant: "danger",
            message: "A different vote, or one without a valid signature, was published with your vote's nonce. Report this to the election's administrators, along with your vote's nonce: " + ballot.nonce,
        }
    }

    if (results != null) {
        return { variant: "success", message: "Your vote is counted in the published results, with a valid signature." }
    }
    return { variant: "success", message: "Your vote is among the published votes, with a valid signature." }
}

interface ElectionVotesProps {
    election: Election;
    user: User | null;
}

// ElectionVotes shows how many votes have been cast in an election, and once it closes and every vote
// is published, the tally, a download of the votes, and a way for the user to check their vote. Once
// an admin publishes the results, the tally is the one they signed.
export default function ElectionVotes({ election, user } : ElectionVotesProps) : React.JSX.Element {
    const [summary, setSummary] = useState<VoteSummary|null>(null);
    const [loadError, setLoadError] = useState("");
    // the published results, once they've been checked: undefined until then, or if they aren't
    // valid, and null if they haven't been published
    const [results, setResults] = useState<VerifiedResults|null|undefined>(undefined);
    const [resultsError, setResultsError] = useState("");
    // incremented to load the results again, once an admin publishes them
    const [resultsVersion, setResultsVersion] = useState(0);
    const [publishing, setPublishing] = useState(false);
    // the step of checking in progress, or null when the vote isn't being checked
    const [step, setStep] = useState<string|null>(null);
    const [result, setResult] = useState<CheckResult|null>(null);
    const [checkError, setCheckError] = useState("");

    // load the summary, and refresh it until every vote is published
    useEffect(() => {
        let cancelled = false
        let timer : number | undefined

        const load = function() {
            getVoteSummary(election.id).then(resp => {
                if (cancelled) {
                    return
                }

                let complete = false
                if (resp == null) {
                    setLoadError("Error connecting to server to load the votes")
                } else if (resp.status_code != 200 || resp.summary == null) {
                    setLoadError("Unknown server error (status " + resp.status_code + ")")
                } else {
                    setLoadError("")
                    setSummary(resp.summary)
                    complete = resp.summary.complete
                }

                if (!complete) {
                    timer = window.setTimeout(load, SUMMARY_REFRESH_MS)
                }
            })
        }
        load()

        return () => {
            cancelled = true
            window.clearTimeout(timer)
        };
    }, [election.id]);

    const complete = summary != null && summary.complete

    // load the published results once every vote is published, since they can't be published sooner,
    // and check their signature before showing them
    useEffect(() => {
        if (!complete) {
            return
        }

        let cancelled = false

        setResultsError("")
        getResults(election.id).then(async resp => {
            if (resp == null) {
                throw new Error("error connecting to server to load the results")
            }
            if (resp.status_code == 404) {
                return null
            }
            if (resp.status_code != 200 || resp.results == null) {
                throw new Error("unknown server error (status " + resp.status_code + ")")
            }

            return await verifyResults(election, resp.results, await getRoot())
        }).then(verified => {
            if (!cancelled) {
                setResults(verified)
            }
        }).catch(error => {
            console.log("error loading the published results", error)
            if (!cancelled) {
                setResults(undefined)
                setResultsError("The published results couldn't be loaded and checked, so this tally is unofficial.")
            }
        })

        return () => { cancelled = true };
    }, [election, complete, resultsVersion]);

    const check = function(download_votes : boolean) {
        if (user == null) {
            return
        }

        setResult(null)
        setCheckError("")

        // results that couldn't be checked aren't used, so the vote is checked against every vote
        checkVote(user, election, results ?? null, download_votes, setStep).then(setResult).catch(error => {
            setCheckError(messageFor(error))
        }).then(() => {
            setStep(null)
        })
    }

    const published = function() {
        setPublishing(false)
        setResultsVersion(version => version + 1)
    }

    if (summary == null) {
        return (
            <>
                <h4>Votes</h4>
                {loadError == "" ? (
                    <p className="text-muted">Loading...</p>
                ) : (
                    <Alert variant="danger">{loadError}</Alert>
                )}
            </>
        )
    }

    return (
        <>
            <h4>Votes</h4>
            <p>
                {summary.votes_cast.toLocaleString()} {summary.votes_cast == 1 ? "vote" : "votes"} cast.{" "}
                {summary.complete ? "Every vote is published." : "The votes and the tally are published once the election closes."}
            </p>
            {summary.complete && (
                <>
                    <TallyTable election={election} tally={results != null ? tallyEntries(election, results.tally) : summary.tally} />
                    {results != null ? (
                        <p className="text-muted small">
                            Signed {new Date(results.signed_timestamp).toLocaleString()} by a global admin,
                            whose key has fingerprint <KeyFingerprint public_key={results.signer_public_key} />.
                            Votes are checked against the root of their hash tree:{" "}
                            <code className="text-break">{results.body.root_hash}</code>
                        </p>
                    ) : resultsError != "" ? (
                        <Alert variant="warning" className="mt-2">{resultsError}</Alert>
                    ) : (
                        <p className="text-muted small">
                            Unofficial: the results haven&apos;t been signed yet.
                        </p>
                    )}
                    <div className="d-flex gap-2 mb-3">
                        <a href={publishedVotesEndpoint(election.id)} className="btn btn-outline-primary">
                            Download the votes
                        </a>
                        {user != null && (
                            <Button variant="outline-primary" onClick={() => check(false)} disabled={step != null}>
                                Check my vote
                            </Button>
                        )}
                        {isGlobalAdmin(user) && results === null && (
                            <Button variant="outline-primary" onClick={() => setPublishing(true)}>
                                Publish results
                            </Button>
                        )}
                    </div>
                    <PublishResultsModal
                        election={election}
                        show={publishing}
                        onHide={() => setPublishing(false)}
                        onPublished={published} />
                </>
            )}
            {step != null && (
                <p>
                    <Spinner as="span" animation="border" size="sm" className="me-2" />
                    {step}...
                </p>
            )}
            {result != null && (
                <Alert variant={result.variant}>
                    {result.message}
                    {result.offer_download && (
                        <div className="mt-2">
                            <Button variant="outline-primary" size="sm" onClick={() => check(true)}>
                                Check against every vote
                            </Button>
                        </div>
                    )}
                </Alert>
            )}
            {checkError != "" && (
                <Alert variant="danger">{checkError}</Alert>
            )}
            {loadError != "" && (
                <Alert variant="warning">{loadError}</Alert>
            )}
        </>
    )
}
