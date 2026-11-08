import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Alert, Breadcrumb, Button, Card } from "react-bootstrap";
import AuditJurisdictionModal from "@/components/auditjurisdictionmodal";
import { getJurisdiction, Jurisdiction } from "@/services/jurisdictionservice";
import { User } from "@/models/user";
import { getUser, isGlobalAdmin } from "@/utils/user";

export default function JurisdictionPage() : React.JSX.Element {
    const [jurisdiction, setJurisdiction] = useState<Jurisdiction|null>(null);
    const [loading, setLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState("");
    const [user, setUser] = useState<User|null>(null);
    const [auditing, setAuditing] = useState(false);
    const {jurisdiction_id} = useParams();

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(setUser)

        // no cleanup necessary
        return () => {};
    }, []);

    useEffect(() => {
        if (typeof jurisdiction_id !== "string") {
            return
        }

        setLoading(true)
        setJurisdiction(null)
        setErrorMessage("")

        getJurisdiction(jurisdiction_id).then(resp => {
            setLoading(false)

            if (resp == null) {
                setErrorMessage("Error connecting to server to load jurisdiction")
                return
            }
            if (resp.status_code == 404) {
                setErrorMessage("Jurisdiction not found")
                return
            }
            if (resp.status_code != 200) {
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            setJurisdiction(resp.jurisdiction)
        })

        // no cleanup necessary
        return () => {};
    }, [jurisdiction_id]);

    return (
        <div className="container">
            <Breadcrumb>
                <Breadcrumb.Item linkAs={Link} linkProps={{ to: "/jurisdictions" }}>
                    Jurisdictions
                </Breadcrumb.Item>
                <Breadcrumb.Item active>
                    {jurisdiction != null ? jurisdiction.name : "Jurisdiction"}
                </Breadcrumb.Item>
            </Breadcrumb>
            <h2 className="text-center">
                {jurisdiction != null ? jurisdiction.name : "Jurisdiction"}
            </h2>
            {loading && (
                <p className="text-center">Loading...</p>
            )}
            {jurisdiction != null && (
                <Card className="mb-3">
                    <Card.Body>
                        <Card.Text>{jurisdiction.info}</Card.Text>
                    </Card.Body>
                    <Card.Footer className="text-muted">
                        Created {new Date(jurisdiction.created_timestamp * 1000).toLocaleString()}
                    </Card.Footer>
                </Card>
            )}
            {jurisdiction != null && (
                // links to the jurisdiction's sections (sub-jurisdictions will go here too)
                <div className="d-flex gap-2 mb-3">
                    <Link to={"/jurisdictions/" + jurisdiction.id + "/elections"} className="btn btn-outline-primary">
                        Elections
                    </Link>
                    {isGlobalAdmin(user) && (
                        <Link to={"/jurisdictions/" + jurisdiction.id + "/voters"} className="btn btn-outline-primary">
                            Voters
                        </Link>
                    )}
                    <Button variant="outline-primary" onClick={() => setAuditing(true)}>
                        Audit
                    </Button>
                </div>
            )}
            {jurisdiction != null && (
                <AuditJurisdictionModal jurisdiction={jurisdiction} show={auditing} onHide={() => setAuditing(false)} />
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
