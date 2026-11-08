import React, { useEffect, useState } from "react";
import { Alert } from "react-bootstrap";
import KeyFingerprint from "@/components/keyfingerprint";
import { Election } from "@/services/electionservice";
import { Jurisdiction } from "@/services/jurisdictionservice";
import { verifyElectionCreation, verifyJurisdictionCreation } from "@/utils/audit";
import { getRoot, Root } from "@/utils/root";

interface CreationCheckProps {
    // one of jurisdiction or election is set: the one whose creation is checked
    jurisdiction?: Jurisdiction;
    election?: Election;
}

// CreationCheck checks the request that created a jurisdiction or an election against the API's root
// (see verifyJurisdictionCreation and verifyElectionCreation), and shows what it found: who signed
// it, by the fingerprints of their key and of the root that issued their certificate, or why it
// doesn't check out
export default function CreationCheck({ jurisdiction, election } : CreationCheckProps) : React.JSX.Element {
    // the root the request checks out against: undefined until it's been checked, and null if it
    // couldn't be, or doesn't check out
    const [root, setRoot] = useState<Root|null|undefined>(undefined);
    const [errorMessage, setErrorMessage] = useState("");

    const noun = election != null ? "election" : "jurisdiction"

    useEffect(() => {
        let cancelled = false

        setRoot(undefined)
        setErrorMessage("")

        getRoot().then(async loaded => {
            try {
                if (election != null) {
                    await verifyElectionCreation(election, loaded)
                } else if (jurisdiction != null) {
                    await verifyJurisdictionCreation(jurisdiction, loaded)
                }
            } catch (error) {
                console.log("the request that created the " + noun + " doesn't check out", error)
                if (!cancelled) {
                    setRoot(null)
                    setErrorMessage(election != null
                        ? "This election doesn't match the request that created it, so its key can't be trusted, and it isn't safe to vote in it. Report this to the election's administrators."
                        : "This jurisdiction doesn't match the request that created it. Report this to the jurisdiction's administrators.")
                }
                return
            }

            if (!cancelled) {
                setRoot(loaded)
            }
        }, error => {
            console.log("error loading the root certificate", error)
            if (!cancelled) {
                setRoot(null)
                setErrorMessage("The server's root certificate couldn't be loaded, so the request that created this " + noun + " couldn't be checked. Try again later.")
            }
        })

        return () => { cancelled = true };
    }, [jurisdiction, election, noun]);

    const signed_request = election != null ? election.signed_request : jurisdiction?.signed_request

    if (root === undefined) {
        return <p className="text-muted">Checking the request that created this {noun}...</p>
    }
    if (root == null || signed_request == null) {
        return <Alert variant="danger">{errorMessage}</Alert>
    }

    return (
        <p>
            A global admin created this {noun}, {election != null ? "with these details, candidates and key" : "with this name and information"}.
            Their key has fingerprint <KeyFingerprint public_key={signed_request.public_key} />, and their
            certificate is from the server&apos;s root, whose key has
            fingerprint <KeyFingerprint public_key={root.public_key} />.
        </p>
    );
}
