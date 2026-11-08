import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert, Breadcrumb, Table } from "react-bootstrap";
import ElectionStatusBadge from "@/components/electionstatusbadge";
import { User } from "@/models/user";
import { ElectionSummary, getElections } from "@/services/electionservice";
import { getJurisdiction, Jurisdiction } from "@/services/jurisdictionservice";
import { getUser, isGlobalAdmin } from "@/utils/user";

export default function JurisdictionElectionsPage() : React.JSX.Element {
    const {jurisdiction_id} = useParams();
    const [jurisdiction, setJurisdiction] = useState<Jurisdiction|null>(null);
    const [user, setUser] = useState<User|null>(null);

    const [elections, setElections] = useState<ElectionSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadFailed, setLoadFailed] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(setUser)

        // no cleanup necessary
        return () => {};
    }, []);

    // load the jurisdiction for its name (errors are shown when loading elections)
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

    useEffect(() => {
        if (typeof jurisdiction_id !== "string") {
            return
        }

        // ignore responses for a jurisdiction that is no longer shown
        let cancelled = false

        setLoading(true)
        setLoadFailed(false)
        setElections([])
        setErrorMessage("")

        getElections(jurisdiction_id).then(resp => {
            if (cancelled) {
                return
            }
            setLoading(false)

            if (resp == null) {
                setLoadFailed(true)
                setErrorMessage("Error connecting to server to load elections")
                return
            }
            if (resp.status_code == 404) {
                setLoadFailed(true)
                setErrorMessage("Jurisdiction not found")
                return
            }
            if (resp.status_code != 200) {
                setLoadFailed(true)
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            setElections(resp.elections)
        })

        return () => { cancelled = true };
    }, [jurisdiction_id]);

    const jurisdictionName = jurisdiction != null ? jurisdiction.name : "Jurisdiction"
    const showEmpty = !loading && !loadFailed && elections.length == 0

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
                    Elections
                </Breadcrumb.Item>
            </Breadcrumb>
            <h2 className="text-center">
                {jurisdictionName} Elections
            </h2>
            {isGlobalAdmin(user) && !loadFailed && (
                <div className="d-flex justify-content-end mb-3">
                    <Link to={"/jurisdictions/" + jurisdiction_id + "/elections/create"} className="btn btn-primary">
                        Create Election
                    </Link>
                </div>
            )}
            {loading && (
                <p className="text-center">Loading...</p>
            )}
            {elections.length > 0 && (
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Opens</th>
                            <th>Closes</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {elections.map(election => (
                            <tr key={election.id}>
                                <td>
                                    <Link to={"/elections/" + election.id}>{election.title}</Link>
                                </td>
                                <td>{new Date(election.time_open * 1000).toLocaleString()}</td>
                                <td>{new Date(election.time_close * 1000).toLocaleString()}</td>
                                <td>
                                    <ElectionStatusBadge time_open={election.time_open} time_close={election.time_close} />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            )}
            {showEmpty && (
                <p className="text-center text-muted">No elections yet.</p>
            )}
            <Alert
                variant="danger"
                onClose={() => setErrorMessage("")}
                show={errorMessage != ""}>
                {errorMessage}
            </Alert>
        </div>
    );
}
