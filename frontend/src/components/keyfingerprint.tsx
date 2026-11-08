import React, { useEffect, useState } from "react";
import { publicKeyFingerprint, shortFingerprint } from "@/utils/keys";

interface KeyFingerprintProps {
    public_key: string;
    // "short" shows the first few groups on one line, "full" shows every group over several lines
    variant?: "short" | "full";
}

// KeyFingerprint shows the fingerprint of a PEM public key, computed locally in the browser
export default function KeyFingerprint({ public_key, variant = "short" } : KeyFingerprintProps) : React.JSX.Element {
    const [fingerprint, setFingerprint] = useState("");

    useEffect(() => {
        let cancelled = false

        setFingerprint("")
        publicKeyFingerprint(public_key).then(computed => {
            if (!cancelled) {
                setFingerprint(computed)
            }
        }).catch(error => {
            console.log("error computing key fingerprint", error)
            if (!cancelled) {
                setFingerprint("invalid key")
            }
        })

        return () => { cancelled = true };
    }, [public_key]);

    if (variant == "short") {
        return <code>{shortFingerprint(fingerprint)}</code>
    }

    // four groups per line, so the full fingerprint is easy to read aloud and compare
    const groups : string[] = fingerprint.split(" ")
    const lines : string[] = []
    for (let i = 0; i < groups.length; i += 4) {
        lines.push(groups.slice(i, i + 4).join(" "))
    }

    return (
        <code className="d-block fs-5">
            {lines.map((line, i) => (
                <div key={i}>{line}</div>
            ))}
        </code>
    );
}
