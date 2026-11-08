import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Alert, Table } from "react-bootstrap";
import { getJurisdictions, JurisdictionSummary } from "@/services/jurisdictionservice";
import { User } from "@/models/user";
import { getUser, isGlobalAdmin } from "@/utils/user";

export default function JurisdictionsPage() : React.JSX.Element {
    const [jurisdictions, setJurisdictions] = useState<JurisdictionSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [loadFailed, setLoadFailed] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");
    const [user, setUser] = useState<User|null>(null);

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(setUser)

        getJurisdictions().then(resp => {
            setLoading(false)

            if (resp == null) {
                setLoadFailed(true)
                setErrorMessage("Error connecting to server to load jurisdictions")
                return
            }
            if (resp.status_code != 200) {
                setLoadFailed(true)
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            setJurisdictions(resp.jurisdictions)
        })

        // no cleanup necessary
        return () => {};
    }, []);

    const showEmpty = !loading && !loadFailed && jurisdictions.length == 0

    return (
        <div className="container">
            <h2 className="text-center">
                Jurisdictions
            </h2>
            {isGlobalAdmin(user) && (
                <div className="justify-end mb-3">
                    <Link to="/jurisdictions/create" className="btn btn-primary">Create Jurisdiction</Link>
                </div>
            )}
            <Table striped bordered hover>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Info</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {jurisdictions.map(jurisdiction => (
                        <tr key={jurisdiction.id}>
                            <td>
                                <Link to={"/jurisdictions/" + jurisdiction.id}>{jurisdiction.name}</Link>
                            </td>
                            <td>{jurisdiction.info}</td>
                            <td>{new Date(jurisdiction.created_timestamp * 1000).toLocaleString()}</td>
                        </tr>
                    ))}
                    {showEmpty && (
                        <tr>
                            <td colSpan={3} className="text-center">
                                No jurisdictions found.
                            </td>
                        </tr>
                    )}
                </tbody>
            </Table>
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
