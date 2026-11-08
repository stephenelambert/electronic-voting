import React, { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Alert, Breadcrumb, Button, Form } from "react-bootstrap";
import { User } from "@/models/user";
import { createElection, createElectionKey } from "@/services/electionservice";
import { getJurisdiction, Jurisdiction } from "@/services/jurisdictionservice";
import { checkElectionPublicKey } from "@/utils/keys";
import { getUser, isGlobalAdmin } from "@/utils/user";

// matches the fewest candidates the API accepts for an election
const MIN_CANDIDATES = 2

interface CandidateRow {
    // only identifies the row for React, so rows keep their inputs when others are removed
    key: string;
    name: string;
    description: string;
}

function newCandidateRow() : CandidateRow {
    return { key: crypto.randomUUID(), name: "", description: "" }
}

// toUnixSeconds converts the value of a datetime-local input, which is in the browser's time zone,
// to a Unix timestamp in seconds
function toUnixSeconds(datetime_local : string) : number {
    return Math.floor(new Date(datetime_local).getTime() / 1000)
}

export default function CreateElectionPage() : React.JSX.Element {
    const navigate = useNavigate();
    const {jurisdiction_id} = useParams();
    const [jurisdiction, setJurisdiction] = useState<Jurisdiction|null>(null);
    const [user, setUser] = useState<User|null>(null);
    const [userLoaded, setUserLoaded] = useState(false);

    // generated once for the form rather than for each request, so resubmitting after a lost
    // response can't create a second election: the server rejects the repeated id instead
    const [electionId] = useState(() => crypto.randomUUID());
    // the election key, requested on the first submit and then kept for retries along with the
    // election id. requesting it on submit rather than on load means visiting the form doesn't leave
    // unclaimed keys behind
    const [publicKey, setPublicKey] = useState<string|null>(null);

    const [formData, setFormData] = useState({
        title: "",
        description: "",
        time_open: "",
        time_close: "",
    });
    const [candidates, setCandidates] = useState<CandidateRow[]>(() => [newCandidateRow(), newCandidateRow()]);
    const [errorMessage, setErrorMessage] = useState("");
    const [alreadyCreated, setAlreadyCreated] = useState(false);
    const [submitting, setSubmitting] = useState(false);

    const isAdmin = isGlobalAdmin(user)

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(maybe_user => {
            setUser(maybe_user)
            setUserLoaded(true)
        })

        // no cleanup necessary
        return () => {};
    }, []);

    // load the jurisdiction for its name
    useEffect(() => {
        if (typeof jurisdiction_id !== "string") {
            return
        }

        getJurisdiction(jurisdiction_id).then(resp => {
            if (resp != null && resp.status_code == 200) {
                setJurisdiction(resp.jurisdiction)
            }
        })

        // no cleanup necessary
        return () => {};
    }, [jurisdiction_id]);

    const handleChange = (event : React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        setFormData({ ...formData, [event.target.name]: event.target.value })
    }

    const updateCandidate = function(index : number, field : "name" | "description", value : string) {
        setCandidates(rows => rows.map((row, i) => i == index ? { ...row, [field]: value } : row))
    }

    const addCandidate = function() {
        setCandidates(rows => [...rows, newCandidateRow()])
    }

    const removeCandidate = function(index : number) {
        setCandidates(rows => rows.filter((_, i) => i != index))
    }

    // getElectionKey resolves to the key for this form's election, requesting and checking one the
    // first time. It resolves to null, after showing why, if there is no key to use.
    const getElectionKey = function(jurisdiction_id : string) : Promise<string|null> {
        if (publicKey != null) {
            return Promise.resolve(publicKey)
        }

        return createElectionKey(jurisdiction_id).then(resp => {
            if (resp == null) {
                setErrorMessage("Error connecting to server to create election key")
                return null
            }
            if (resp.status_code == 401) {
                setErrorMessage("Unauthorized to create elections")
                return null
            }
            if (resp.status_code == 404) {
                setErrorMessage("Jurisdiction not found")
                return null
            }
            if (resp.status_code != 201) {
                setErrorMessage("Unknown server error creating election key (status " + resp.status_code + ")")
                return null
            }

            // the signed request to create the election vouches for the key, so only accept a
            // sound one
            const public_key = resp.public_key
            return checkElectionPublicKey(public_key).then(() => {
                setPublicKey(public_key)
                return public_key
            }, error => {
                console.log("election key check failed", error)
                setErrorMessage("The election key from the server failed checks")
                return null
            })
        })
    }

    const submitForm = function(event : React.FormEvent<HTMLFormElement>) {
        event.preventDefault()

        setErrorMessage("")
        setAlreadyCreated(false)

        const form = event.currentTarget;
        if (form.checkValidity() === false || typeof jurisdiction_id !== "string") {
            return
        }

        const time_open = toUnixSeconds(formData.time_open)
        const time_close = toUnixSeconds(formData.time_close)

        // the API checks these too, but checking here gives clearer messages
        if (formData.title.trim() == "") {
            setErrorMessage("The election needs a title")
            return
        }
        if (candidates.some(row => row.name.trim() == "")) {
            setErrorMessage("Every candidate needs a name")
            return
        }
        if (time_open <= Date.now() / 1000) {
            setErrorMessage("The election must open in the future")
            return
        }
        if (time_close <= time_open) {
            setErrorMessage("The election must close after it opens")
            return
        }

        // disable the form until the requests finish, so they can't be sent again in the meantime
        setSubmitting(true)

        getElectionKey(jurisdiction_id).then(public_key => {
            if (public_key == null) {
                setSubmitting(false)
                return
            }

            return createElection(jurisdiction_id, {
                id: electionId,
                title: formData.title,
                description: formData.description,
                time_open,
                time_close,
                public_key,
                candidates: candidates.map(row => ({ name: row.name, description: row.description })),
            }).then(resp => {
                setSubmitting(false)

                if (resp == null) {
                    setErrorMessage("Error connecting to server to create election")
                    return
                }
                if (resp.status_code == 409) {
                    // the id and key are only generated once per form, so an earlier attempt went
                    // through
                    setAlreadyCreated(true)
                    return
                }
                if (resp.status_code == 400) {
                    setErrorMessage("The server rejected the election. Check that it opens in the future and closes after it opens.")
                    return
                }
                if (resp.status_code == 401) {
                    setErrorMessage("Unauthorized to create elections")
                    return
                }
                if (resp.status_code == 404) {
                    setErrorMessage("Jurisdiction not found")
                    return
                }
                if (resp.status_code != 201) {
                    setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                    return
                }

                navigate("/elections/" + electionId)
            })
        }).catch(error => {
            // createElectionKey and createElection throw if they can't build their requests, e.g. if
            // the user's key can't be loaded or used to sign them
            console.log("error preparing election request", error)
            setSubmitting(false)
            setErrorMessage("Error preparing the request to create election")
        })
    }

    const jurisdictionName = jurisdiction != null ? jurisdiction.name : "Jurisdiction"

    return (
        <div className="container">
            <Breadcrumb>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions" }}>
                    Jurisdictions
                </Breadcrumb.Item>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions/" + jurisdiction_id }}>
                    {jurisdictionName}
                </Breadcrumb.Item>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions/" + jurisdiction_id + "/elections" }}>
                    Elections
                </Breadcrumb.Item>
                <Breadcrumb.Item active>
                    Create
                </Breadcrumb.Item>
            </Breadcrumb>
            <h2 className="text-center">
                Create an Election
            </h2>
            {userLoaded && !isAdmin && (
                <Alert variant="warning">
                    You need to be a global admin to create elections.
                </Alert>
            )}
            <Form onSubmit={submitForm}>
                <fieldset disabled={!isAdmin || submitting}>
                <Form.Group className="mb-3" controlId="formTitle">
                    <Form.Label>Title</Form.Label>
                    <Form.Control
                        required
                        type="text"
                        placeholder="Enter title"
                        name="title"
                        value={formData.title}
                        onChange={handleChange}
                    />
                </Form.Group>
                <Form.Group className="mb-3" controlId="formDescription">
                    <Form.Label>Description</Form.Label>
                    <Form.Control
                        as="textarea"
                        rows={3}
                        placeholder="Enter description"
                        name="description"
                        value={formData.description}
                        onChange={handleChange}
                    />
                </Form.Group>
                <div className="d-flex gap-3">
                    <Form.Group className="mb-3 flex-fill" controlId="formTimeOpen">
                        <Form.Label>Opens</Form.Label>
                        <Form.Control
                            required
                            type="datetime-local"
                            name="time_open"
                            value={formData.time_open}
                            onChange={handleChange}
                        />
                    </Form.Group>
                    <Form.Group className="mb-3 flex-fill" controlId="formTimeClose">
                        <Form.Label>Closes</Form.Label>
                        <Form.Control
                            required
                            type="datetime-local"
                            name="time_close"
                            value={formData.time_close}
                            onChange={handleChange}
                        />
                    </Form.Group>
                </div>
                <h4>Candidates</h4>
                <p className="text-muted">Candidates appear on the ballot in this order.</p>
                {candidates.map((row, index) => (
                    <div key={row.key} className="d-flex gap-2 mb-2 align-items-center">
                        <span>{index + 1}.</span>
                        <Form.Control
                            required
                            type="text"
                            placeholder="Name"
                            aria-label={"Candidate " + (index + 1) + " name"}
                            value={row.name}
                            onChange={event => updateCandidate(index, "name", event.target.value)}
                        />
                        <Form.Control
                            type="text"
                            placeholder="Description"
                            aria-label={"Candidate " + (index + 1) + " description"}
                            value={row.description}
                            onChange={event => updateCandidate(index, "description", event.target.value)}
                        />
                        <Button
                            variant="outline-danger"
                            disabled={candidates.length <= MIN_CANDIDATES}
                            onClick={() => removeCandidate(index)}>
                            Remove
                        </Button>
                    </div>
                ))}
                <Button variant="outline-secondary" className="mb-3" onClick={addCandidate}>
                    Add Candidate
                </Button>
                <div>
                    <Button variant="primary" type="submit">
                        {submitting ? "Creating..." : "Create"}
                    </Button>
                </div>
                </fieldset>
            </Form>
            <Alert variant="info" className="mt-3" show={alreadyCreated}>
                This election was already created by an earlier attempt, so changes made since then
                weren&apos;t saved. <Link to={"/elections/" + electionId} className="alert-link">View the election</Link>
            </Alert>
            <Alert
                variant="danger"
                className="mt-3"
                onClose={() => setErrorMessage("")}
                show={errorMessage != ""}
                dismissible>
                {errorMessage}
            </Alert>
        </div>
    );
}
