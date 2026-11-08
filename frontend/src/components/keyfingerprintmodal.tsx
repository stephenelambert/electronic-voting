import React from "react";
import { Button, Modal } from "react-bootstrap";
import KeyFingerprint from "@/components/keyfingerprint";

interface KeyFingerprintModalProps {
    public_key: string;
    show: boolean;
    onHide: () => void;
}

// KeyFingerprintModal shows the signed-in user the fingerprint of their own key, so a registrar
// authorizing them can confirm they are authorizing the right key
export default function KeyFingerprintModal({ public_key, show, onHide } : KeyFingerprintModalProps) : React.JSX.Element {
    return (
        <Modal show={show} onHide={onHide} centered>
            <Modal.Header closeButton>
                <Modal.Title>Your Key Fingerprint</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <p>
                    When a registrar authorizes you as a voter, they should confirm that the
                    fingerprint they see matches this one.
                </p>
                <div className="text-center">
                    <KeyFingerprint public_key={public_key} variant="full" />
                </div>
            </Modal.Body>
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide}>Close</Button>
            </Modal.Footer>
        </Modal>
    );
}
