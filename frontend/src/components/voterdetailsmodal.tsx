import React, { useEffect, useState } from "react";
import { Alert, Button, Modal } from "react-bootstrap";
import KeyFingerprint from "@/components/keyfingerprint";
import { Voter } from "@/services/voterservice";
import { verifyVoterAuthorization } from "@/utils/audit";
import { arrayBufferToBase64 } from "@/utils/base64";
import { publicKeyPEMToDER } from "@/utils/keys";
import { getRoot } from "@/utils/root";

// checkAuthorization checks a voter's authorization in the jurisdiction (see
// verifyVoterAuthorization), and that it's for the key on their account. It throws otherwise.
async function checkAuthorization(jurisdiction_id : string, voter : Voter) : Promise<void> {
    const voter_key = await verifyVoterAuthorization(jurisdiction_id, voter, await getRoot())
    if (voter_key !== arrayBufferToBase64(publicKeyPEMToDER(voter.public_key))) {
        throw new Error("authorization is for another key")
    }
}

interface AuthorizationCheckProps {
    jurisdiction_id: string;
    voter: Voter;
}

// AuthorizationCheck checks a voter's authorization, and shows the fingerprint of the admin who
// signed it, or why it doesn't check out
function AuthorizationCheck({ jurisdiction_id, voter } : AuthorizationCheckProps) : React.JSX.Element {
    // whether the authorization checks out: undefined until it's been checked
    const [valid, setValid] = useState<boolean|undefined>(undefined);
    const [problem, setProblem] = useState("");

    useEffect(() => {
        let cancelled = false

        setValid(undefined)
        setProblem("")
        checkAuthorization(jurisdiction_id, voter).then(() => {
            if (!cancelled) {
                setValid(true)
            }
        }).catch(error => {
            console.log("error checking the voter's authorization", error)
            if (!cancelled) {
                setValid(false)
                setProblem(error instanceof Error ? error.message : String(error))
            }
        })

        return () => { cancelled = true };
    }, [jurisdiction_id, voter]);

    if (valid === undefined) {
        return <p className="text-muted">Checking the authorization...</p>
    }
    if (!valid) {
        return <Alert variant="danger">This voter&apos;s authorization couldn&apos;t be confirmed ({problem}).</Alert>
    }

    return (
        <p>
            A global admin authorized this voter&apos;s key. The admin&apos;s key has
            fingerprint <KeyFingerprint public_key={voter.authorization.public_key} />, and their signed
            request and this voter&apos;s certificate check out against the server&apos;s root.
        </p>
    );
}

interface VoterDetailsModalProps {
    // jurisdiction_id is the jurisdiction the voter is listed in
    jurisdiction_id: string;
    // the modal is shown while voter is not null
    voter: Voter | null;
    onHide: () => void;
}

const pemStyle : React.CSSProperties = { whiteSpace: "pre-wrap", wordBreak: "break-all" }

// VoterDetailsModal shows a voter's full key fingerprint, public key, and authorization certificate,
// and checks the admin's signed request that authorized them
export default function VoterDetailsModal({ jurisdiction_id, voter, onHide } : VoterDetailsModalProps) : React.JSX.Element {
    return (
        <Modal show={voter != null} onHide={onHide} size="lg">
            <Modal.Header closeButton>
                <Modal.Title>Voter {voter?.username}</Modal.Title>
            </Modal.Header>
            {voter != null && (
                <Modal.Body>
                    <p className="mb-1">
                        Authorized {new Date(voter.authorized_timestamp * 1000).toLocaleString()}
                    </p>
                    <AuthorizationCheck jurisdiction_id={jurisdiction_id} voter={voter} />
                    <h6>Key Fingerprint</h6>
                    <KeyFingerprint public_key={voter.public_key} variant="full" />
                    <h6 className="mt-3">Public Key</h6>
                    <pre style={pemStyle}>{voter.public_key}</pre>
                    <h6>Certificate</h6>
                    <p className="mb-1">ID: <code>{voter.certificate.id}</code></p>
                    <pre style={pemStyle}>{voter.certificate.cert_pem}</pre>
                </Modal.Body>
            )}
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>Close</Button>
            </Modal.Footer>
        </Modal>
    );
}
