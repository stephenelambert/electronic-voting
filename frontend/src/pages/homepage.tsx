import React from "react";
import { Link } from "react-router-dom";

export default function Homepage() : React.JSX.Element {
    return (
        <div className="container">
            <h2 className="text-center">
                Electronic Voting
            </h2>
            <p>
                This electronic voting system aims to be a secure method of voting, where individuals can cryptographically verify that their vote has been counted while preserving the privacy of their actual vote from the server.
            </p>
            <Link to="/jurisdictions" className="btn btn-primary">Jurisdictions</Link>
        </div>
    );
}
