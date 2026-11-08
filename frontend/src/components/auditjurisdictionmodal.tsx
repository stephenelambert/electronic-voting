import React, { useState } from "react";
import { Alert, Button, Modal, Spinner } from "react-bootstrap";
import AuthorizerList from "@/components/authorizerlist";
import CreationCheck from "@/components/creationcheck";
import { Jurisdiction } from "@/services/jurisdictionservice";
import { getVoterAuthorizations } from "@/services/voterservice";
import { auditVoterAuthorizations, verifyJurisdictionCreation, VoterAuthorizationAudit } from "@/utils/audit";
import { getRoot, Root } from "@/utils/root";

// CountError is an error counting a jurisdiction's voters, with a message to show the user
class CountError extends Error {}

// countVoters downloads every published voter authorization in the jurisdiction, and resolves to how
// many voters they authorize and which admins' keys authorized them, once each one checks out (see
// auditVoterAuthorizations). onStep reports progress.
async function countVoters(jurisdiction : Jurisdiction, onStep : (step : string) => void) : Promise<VoterAuthorizationAudit> {
    onStep("Downloading the voter authorizations")
    const resp = await getVoterAuthorizations(jurisdiction.id)
    if (resp == null) {
        throw new CountError("Error connecting to server to fetch the voter authorizations")
    }
    if (resp.status_code != 200) {
        throw new CountError("Unknown server error (status " + resp.status_code + ")")
    }

    let root : Root
    try {
        root = await getRoot()
    } catch (error) {
        console.log("error loading the root certificate", error)
        throw new CountError("The server's root certificate couldn't be loaded, so the voter authorizations couldn't be checked. Try again later.")
    }

    // the count marks the key that created the jurisdiction, so that request has to check out too
    try {
        await verifyJurisdictionCreation(jurisdiction, root)
    } catch (error) {
        console.log("the request that created the jurisdiction doesn't check out", error)
        throw new CountError("This jurisdiction doesn't match the request that created it, so its voters can't be counted. Report this to the jurisdiction's administrators.")
    }

    onStep("Checking " + resp.authorizations.length.toLocaleString() + " voter authorizations")
    try {
        return await auditVoterAuthorizations(jurisdiction, resp.authorizations, root)
    } catch (error) {
        throw new CountError("The voter authorizations don't check out (" + (error instanceof Error ? error.message : String(error)) + "). Report this to the jurisdiction's administrators.")
    }
}

interface VoterCountProps {
    jurisdiction: Jurisdiction;
}

// VoterCount counts a jurisdiction's voters when asked, checking each one's published authorization,
// and lists the admins' keys that authorized them
function VoterCount({ jurisdiction } : VoterCountProps) : React.JSX.Element {
    // the step of counting in progress, or null when the voters aren't being counted
    const [step, setStep] = useState<string|null>(null);
    const [audit, setAudit] = useState<VoterAuthorizationAudit|null>(null);
    const [errorMessage, setErrorMessage] = useState("");

    const countAll = function() {
        setAudit(null)
        setErrorMessage("")

        countVoters(jurisdiction, setStep).then(setAudit).catch(error => {
            if (error instanceof CountError) {
                setErrorMessage(error.message)
            } else {
                console.log("error counting the voters", error)
                setErrorMessage("Error counting the voters")
            }
        }).then(() => {
            setStep(null)
        })
    }

    return (
        <>
            <p className="text-muted">
                Counting downloads every voter authorization in this jurisdiction, and checks that a
                global admin authorized each voter&apos;s key and the server&apos;s root issued each
                voter&apos;s certificate. Voters, and the admins who authorized them, are listed by
                key, not by name.
            </p>
            <Button variant="outline-primary" onClick={countAll} disabled={step != null}>
                Count the voters
            </Button>
            {step != null && (
                <p className="mt-3 mb-0">
                    <Spinner as="span" animation="border" size="sm" className="me-2" />
                    {step}...
                </p>
            )}
            {audit != null && (
                <div className="mt-3">
                    <p className={audit.authorizers.length > 0 ? "mb-2" : "mb-0"}>
                        {audit.voters.toLocaleString()} {audit.voters == 1 ? "voter is" : "voters are"} authorized
                        in this jurisdiction, and every authorization checks out.
                        {audit.authorizers.length > 0 && (
                            <>
                                {" "}They were authorized
                                by {audit.authorizers.length.toLocaleString()} global admin {audit.authorizers.length == 1 ? "key" : "keys"},
                                listed by fingerprint. Check that each is one of the real global admins&apos; keys:
                                one that isn&apos;t could be a key the server issued itself, to authorize extra voters.
                            </>
                        )}
                    </p>
                    {audit.authorizers.length > 0 && (
                        <AuthorizerList authorizers={audit.authorizers} noun="jurisdiction" />
                    )}
                </div>
            )}
            {errorMessage != "" && (
                <Alert variant="danger" className="mt-3 mb-0">{errorMessage}</Alert>
            )}
        </>
    );
}

interface AuditJurisdictionModalProps {
    jurisdiction: Jurisdiction;
    show: boolean;
    onHide: () => void;
}

// AuditJurisdictionModal checks the request that created a jurisdiction, and can count its voters,
// checking each one's authorization. The modal's body only exists while it's open, so closing it
// drops what it found, and a count still running is ignored.
export default function AuditJurisdictionModal({ jurisdiction, show, onHide } : AuditJurisdictionModalProps) : React.JSX.Element {
    return (
        <Modal show={show} onHide={onHide} size="lg">
            <Modal.Header closeButton>
                <Modal.Title>Audit {jurisdiction.name}</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <h6>Creation</h6>
                <CreationCheck jurisdiction={jurisdiction} />
                <h6 className="mt-3">Voters</h6>
                <VoterCount jurisdiction={jurisdiction} />
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>Close</Button>
            </Modal.Footer>
        </Modal>
    );
}
