import React from "react";
import KeyFingerprint from "@/components/keyfingerprint";
import { Authorizer } from "@/utils/audit";

interface AuthorizerListProps {
    authorizers: Authorizer[];
    // noun is what was audited, "jurisdiction" or "election", for marking the key that created it
    noun: string;
}

// AuthorizerList lists the global admins' keys that authorized voters (see Authorizer) by their
// fingerprints, with how many voters each authorized, and marks the key that created the jurisdiction
// or election
export default function AuthorizerList({ authorizers, noun } : AuthorizerListProps) : React.JSX.Element {
    return (
        <ul className="mb-0">
            {authorizers.map(authorizer => (
                <li key={authorizer.public_key}>
                    <KeyFingerprint public_key={authorizer.public_key} />: {authorizer.voters.toLocaleString()} {authorizer.voters == 1 ? "voter" : "voters"}
                    {authorizer.creator && ", and created this " + noun}
                </li>
            ))}
        </ul>
    );
}
