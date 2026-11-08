import React, { useEffect, useState } from "react";
import { Alert, Button, Form, ListGroup, Modal } from "react-bootstrap";
import KeyFingerprint from "@/components/keyfingerprint";
import { AccountSearchResult, searchAccounts } from "@/services/accountservice";
import { authorizeVoter } from "@/services/voterservice";
import { useDebouncedValue } from "@/utils/hooks";

// matches the maximum number of results the API returns for an account search
const SEARCH_LIMIT = 25

interface AuthorizeVoterModalProps {
    jurisdiction_id: string;
    show: boolean;
    onHide: () => void;
    // called with the username of the account after it is authorized
    onAuthorized: (username : string) => void;
}

// AuthorizeVoterModal lets an admin search for an account by username, confirm its key fingerprint,
// and authorize it as a voter in the jurisdiction
export default function AuthorizeVoterModal({ jurisdiction_id, show, onHide, onAuthorized } : AuthorizeVoterModalProps) : React.JSX.Element {
    const [searchInput, setSearchInput] = useState("");
    const debouncedSearch = useDebouncedValue(searchInput.trim(), 300);
    const [results, setResults] = useState<AccountSearchResult[]>([]);
    const [searching, setSearching] = useState(false);
    const [selected, setSelected] = useState<AccountSearchResult|null>(null);
    const [submitting, setSubmitting] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");

    useEffect(() => {
        if (debouncedSearch == "") {
            setResults([])
            setSearching(false)
            return
        }

        let cancelled = false
        setSearching(true)

        searchAccounts(debouncedSearch).then(resp => {
            if (cancelled) {
                return
            }
            setSearching(false)

            if (resp == null) {
                setErrorMessage("Error connecting to server to search accounts")
                return
            }
            if (resp.status_code == 401) {
                setErrorMessage("You are not authorized to search accounts")
                return
            }
            if (resp.status_code != 200) {
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            setErrorMessage("")
            setResults(resp.accounts)
        })

        return () => { cancelled = true };
    }, [debouncedSearch]);

    // clear everything once the modal has closed, so it opens fresh next time
    const reset = function() {
        setSearchInput("")
        setResults([])
        setSearching(false)
        setSelected(null)
        setSubmitting(false)
        setErrorMessage("")
    }

    const submit = function() {
        if (selected == null) {
            return
        }

        setSubmitting(true)
        setErrorMessage("")

        authorizeVoter(jurisdiction_id, selected.public_key).then(resp => {
            setSubmitting(false)

            if (resp == null) {
                setErrorMessage("Error connecting to server to authorize voter")
                return
            }
            if (resp.status_code == 409) {
                setErrorMessage(selected.username + " is already authorized in this jurisdiction")
                return
            }
            if (resp.status_code == 404) {
                setErrorMessage("That account no longer has this key, or the jurisdiction no longer exists")
                return
            }
            if (resp.status_code == 401) {
                setErrorMessage("You are not authorized to authorize voters")
                return
            }
            if (resp.status_code != 201) {
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            onAuthorized(selected.username)
        })
    }

    return (
        <Modal show={show} onHide={onHide} onExited={reset}>
            <Modal.Header closeButton>
                <Modal.Title>Authorize Voter</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {selected == null ? (
                    <>
                        <Form.Group className="mb-3" controlId="authorizeVoterSearch">
                            <Form.Label>Username</Form.Label>
                            <Form.Control
                                type="text"
                                placeholder="Start typing a username"
                                autoFocus
                                value={searchInput}
                                onChange={event => setSearchInput(event.target.value)}
                            />
                        </Form.Group>
                        {searching && (
                            <p className="text-muted">Searching...</p>
                        )}
                        {!searching && debouncedSearch != "" && results.length == 0 && errorMessage == "" && (
                            <p className="text-muted">No accounts found.</p>
                        )}
                        {results.length > 0 && (
                            <ListGroup>
                                {results.map(account => (
                                    <ListGroup.Item
                                        key={account.username}
                                        action
                                        onClick={() => setSelected(account)}
                                        className="d-flex justify-content-between">
                                        <span>{account.username}</span>
                                        <KeyFingerprint public_key={account.public_key} />
                                    </ListGroup.Item>
                                ))}
                            </ListGroup>
                        )}
                        {results.length == SEARCH_LIMIT && (
                            <p className="text-muted mt-2">
                                Showing the first {SEARCH_LIMIT} matches; type more to narrow the search.
                            </p>
                        )}
                    </>
                ) : (
                    <>
                        <p>
                            Authorize <strong>{selected.username}</strong> as a voter with the key
                            fingerprint:
                        </p>
                        <div className="text-center mb-3">
                            <KeyFingerprint public_key={selected.public_key} variant="full" />
                        </div>
                        <Alert variant="warning">
                            Before authorizing, confirm this fingerprint matches the one shown on the
                            voter&apos;s own device (under their user menu).
                        </Alert>
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
                {selected == null ? (
                    <Button variant="secondary" onClick={onHide}>Cancel</Button>
                ) : (
                    <>
                        <Button
                            variant="secondary"
                            disabled={submitting}
                            onClick={() => { setSelected(null); setErrorMessage("") }}>
                            Back
                        </Button>
                        <Button variant="primary" disabled={submitting} onClick={submit}>
                            {submitting ? "Authorizing..." : "Authorize"}
                        </Button>
                    </>
                )}
            </Modal.Footer>
        </Modal>
    );
}
