import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { User } from "@/models/user";
import { getUser, logout } from "../utils/user";
import Dropdown from "react-bootstrap/Dropdown";
import DropdownButton from "react-bootstrap/DropdownButton";
import KeyFingerprintModal from "@/components/keyfingerprintmodal";

const paths_without_user_buttons : string[] = ["/register", "/login"];

export default function HeaderBar() : React.JSX.Element {
    const [user, setUser] = useState<User|null>(null)
    const [showFingerprint, setShowFingerprint] = useState(false)
    const location = useLocation();

    const hide_user_buttons = paths_without_user_buttons.includes(location.pathname)

    // load the user from local/session storage without infinitely re-rendering
    useEffect(() => {
        getUser().then(maybe_user => {
            setUser(maybe_user);
        });
        // don't worry about cleanup for this effect
        return () =>{}
    }, [location.pathname])

    const logoutFunc : React.MouseEventHandler<HTMLElement> = (event : React.MouseEvent<HTMLElement, MouseEvent>) : void => {
        event.preventDefault();
        logout().then(() => {
            // force full reload of the page after logging out
            window.location.reload();
        });
    }

    const buildRightButtons = (maybe_user: User | null) : React.JSX.Element => {
        if (maybe_user === null)
            return (
                <>
                    <div className="flexbox">
                        <Link to="/login" className="btn btn-primary">Sign In</Link>
                        <Link to="/register" className="btn btn-outline-primary">Sign Up</Link>
                    </div>
                </>
            );
        else 
            return (
                <>
                    <div className="flexbox">
                        <DropdownButton title={"User " + maybe_user.username}>
                            <Dropdown.Item onClick={() => setShowFingerprint(true)}>Key Fingerprint</Dropdown.Item>
                            <Dropdown.Item onClick={logoutFunc}>Log Out</Dropdown.Item>
                        </DropdownButton>
                        <KeyFingerprintModal
                            public_key={maybe_user.public_key}
                            show={showFingerprint}
                            onHide={() => setShowFingerprint(false)}
                        />
                    </div>
                </>
            );
    };
    return (
        <>
        <div className="full-window-width">
            <div className="header-padding flexbox">
                <div className="flexbox align-items-center">
                    <Link to={"/"}>Electronic Voting</Link>
                    <Link to="/jurisdictions" className="btn btn-primary ms-3">Jurisdictions</Link>
                </div>
                <div className="flex-auto justify-end" hidden={hide_user_buttons}>
                    {buildRightButtons(user)}
                </div>
            </div>
        </div>
        </>
    );
}