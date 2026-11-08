import React, { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Alert, Breadcrumb, Button, Form, Pagination, Table } from "react-bootstrap";
import AuthorizeVoterModal from "@/components/authorizevotermodal";
import KeyFingerprint from "@/components/keyfingerprint";
import VoterDetailsModal from "@/components/voterdetailsmodal";
import { User } from "@/models/user";
import { getJurisdiction, Jurisdiction } from "@/services/jurisdictionservice";
import { getVoters, Voter } from "@/services/voterservice";
import { useDebouncedValue } from "@/utils/hooks";
import { getUser, isGlobalAdmin } from "@/utils/user";

const PAGE_SIZE = 50

// number of page links shown around the current page
const PAGE_WINDOW = 5

export default function JurisdictionVotersPage() : React.JSX.Element {
    const {jurisdiction_id} = useParams();
    const [jurisdiction, setJurisdiction] = useState<Jurisdiction|null>(null);
    const [user, setUser] = useState<User|null>(null);
    const [userLoaded, setUserLoaded] = useState(false);

    const [voters, setVoters] = useState<Voter[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(false);
    const [loadFailed, setLoadFailed] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");
    const [successMessage, setSuccessMessage] = useState("");
    const [refreshCount, setRefreshCount] = useState(0);

    const [showAuthorize, setShowAuthorize] = useState(false);
    const [detailsVoter, setDetailsVoter] = useState<Voter|null>(null);

    // the page and filter live in the URL, so refreshing, going back, and sharing links keep them
    const [searchParams, setSearchParams] = useSearchParams();
    const usernameParam = searchParams.get("username") ?? "";
    const parsedPage = parseInt(searchParams.get("page") ?? "1", 10);
    const page = isNaN(parsedPage) || parsedPage < 1 ? 1 : parsedPage;

    const [filterInput, setFilterInput] = useState(usernameParam);
    const debouncedFilter = useDebouncedValue(filterInput.trim(), 300);

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

    // load the jurisdiction for its name (errors are shown when loading voters)
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

    // put the filter into the URL once typing pauses, going back to the first page
    useEffect(() => {
        if (debouncedFilter == usernameParam) {
            return
        }

        setSearchParams(prev => {
            const next = new URLSearchParams(prev)
            if (debouncedFilter == "") {
                next.delete("username")
            } else {
                next.set("username", debouncedFilter)
            }
            next.delete("page")
            return next
        }, { replace: true })
    }, [debouncedFilter]);

    // keep the filter box in sync when the URL changes from navigation (e.g. going back)
    useEffect(() => {
        if (usernameParam != debouncedFilter) {
            setFilterInput(usernameParam)
        }
    }, [usernameParam]);

    useEffect(() => {
        if (typeof jurisdiction_id !== "string" || !isAdmin) {
            return
        }

        // ignore responses for pages or filters that are no longer shown
        let cancelled = false

        setLoading(true)
        setLoadFailed(false)

        getVoters(jurisdiction_id, {
            limit: PAGE_SIZE,
            offset: (page - 1) * PAGE_SIZE,
            username: usernameParam,
        }).then(resp => {
            if (cancelled) {
                return
            }
            setLoading(false)

            if (resp == null) {
                setLoadFailed(true)
                setErrorMessage("Error connecting to server to load voters")
                return
            }
            if (resp.status_code == 404) {
                setLoadFailed(true)
                setErrorMessage("Jurisdiction not found")
                return
            }
            if (resp.status_code == 401) {
                setLoadFailed(true)
                setErrorMessage("You need to be a global admin to view voters")
                return
            }
            if (resp.status_code != 200) {
                setLoadFailed(true)
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            setErrorMessage("")
            setVoters(resp.voters)
            setTotal(resp.total)
        })

        return () => { cancelled = true };
    }, [jurisdiction_id, isAdmin, page, usernameParam, refreshCount]);

    const goToPage = function(target : number) {
        setSearchParams(prev => {
            const next = new URLSearchParams(prev)
            if (target <= 1) {
                next.delete("page")
            } else {
                next.set("page", target.toString())
            }
            return next
        })
    }

    const onAuthorized = function(username : string) {
        setShowAuthorize(false)
        setSuccessMessage(username + " is now authorized to vote in this jurisdiction")
        setRefreshCount(count => count + 1)
    }

    const jurisdictionName = jurisdiction != null ? jurisdiction.name : "Jurisdiction"
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
    const showEmpty = !loading && !loadFailed && voters.length == 0

    const buildPagination = function() : React.JSX.Element | null {
        if (totalPages <= 1) {
            return null
        }

        let start = Math.max(1, page - Math.floor(PAGE_WINDOW / 2))
        const end = Math.min(totalPages, start + PAGE_WINDOW - 1)
        start = Math.max(1, end - PAGE_WINDOW + 1)

        const items : React.JSX.Element[] = []
        for (let target = start; target <= end; target++) {
            items.push(
                <Pagination.Item key={target} active={target == page} onClick={() => goToPage(target)}>
                    {target}
                </Pagination.Item>
            )
        }

        return (
            <Pagination className="justify-content-center">
                <Pagination.First disabled={page <= 1} onClick={() => goToPage(1)} />
                <Pagination.Prev disabled={page <= 1} onClick={() => goToPage(page - 1)} />
                {items}
                <Pagination.Next disabled={page >= totalPages} onClick={() => goToPage(page + 1)} />
                <Pagination.Last disabled={page >= totalPages} onClick={() => goToPage(totalPages)} />
            </Pagination>
        );
    }

    const emptyMessage = function() : string {
        if (total > 0) {
            return "No voters on this page."
        }
        if (usernameParam != "") {
            return "No voters match \"" + usernameParam + "\"."
        }
        return "No voters authorized yet."
    }

    return (
        <div className="container">
            <Breadcrumb>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions" }}>
                    Jurisdictions
                </Breadcrumb.Item>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions/" + jurisdiction_id }}>
                    {jurisdictionName}
                </Breadcrumb.Item>
                <Breadcrumb.Item active>
                    Voters
                </Breadcrumb.Item>
            </Breadcrumb>
            <h2 className="text-center">
                {jurisdictionName} Voters
            </h2>
            {userLoaded && !isAdmin && (
                <Alert variant="warning">
                    You need to be a global admin to view voters.
                </Alert>
            )}
            {isAdmin && (
                <>
                    <div className="d-flex gap-2 mb-3">
                        <Form.Control
                            type="search"
                            placeholder="Filter by username"
                            aria-label="Filter by username"
                            value={filterInput}
                            onChange={event => setFilterInput(event.target.value)}
                        />
                        <Button
                            variant="primary"
                            className="text-nowrap"
                            onClick={() => setShowAuthorize(true)}>
                            Authorize Voter
                        </Button>
                    </div>
                    <Alert
                        variant="success"
                        onClose={() => setSuccessMessage("")}
                        show={successMessage != ""}
                        dismissible>
                        {successMessage}
                    </Alert>
                    <Table striped bordered hover>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Authorized</th>
                                <th>Key Fingerprint</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {voters.map(voter => (
                                <tr key={voter.certificate.id}>
                                    <td>{voter.username}</td>
                                    <td>{new Date(voter.authorized_timestamp * 1000).toLocaleString()}</td>
                                    <td><KeyFingerprint public_key={voter.public_key} /></td>
                                    <td>
                                        <Button variant="link" size="sm" className="p-0" onClick={() => setDetailsVoter(voter)}>
                                            View
                                        </Button>
                                    </td>
                                </tr>
                            ))}
                            {loading && voters.length == 0 && (
                                <tr>
                                    <td colSpan={4} className="text-center">Loading...</td>
                                </tr>
                            )}
                            {showEmpty && (
                                <tr>
                                    <td colSpan={4} className="text-center">{emptyMessage()}</td>
                                </tr>
                            )}
                        </tbody>
                    </Table>
                    {total > 0 && voters.length > 0 && (
                        <p className="text-center text-muted">
                            Showing {((page - 1) * PAGE_SIZE + 1).toLocaleString()}–
                            {((page - 1) * PAGE_SIZE + voters.length).toLocaleString()} of {total.toLocaleString()} voters
                        </p>
                    )}
                    {buildPagination()}
                    {typeof jurisdiction_id === "string" && (
                        <>
                            <AuthorizeVoterModal
                                jurisdiction_id={jurisdiction_id}
                                show={showAuthorize}
                                onHide={() => setShowAuthorize(false)}
                                onAuthorized={onAuthorized}
                            />
                            <VoterDetailsModal jurisdiction_id={jurisdiction_id} voter={detailsVoter} onHide={() => setDetailsVoter(null)} />
                        </>
                    )}
                </>
            )}
            <Alert
                variant="danger"
                onClose={() => setErrorMessage("")}
                show={errorMessage != ""}
                dismissible>
                {errorMessage}
            </Alert>
        </div>
    );
}
