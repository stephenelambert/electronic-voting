import { createJurisdiction, getJurisdiction } from "@/services/jurisdictionservice";
import { User } from "models/user";
import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getUser, isGlobalAdmin } from "@/utils/user";
import { Alert, Button, Form } from "react-bootstrap";

export default function CreateJurisdictionPage() : React.JSX.Element {
    const navigate = useNavigate();
    const [user, setUser] = useState<User|null>(null)

    // generated once for the form rather than for each request, so resubmitting after a lost
    // response can't create a second jurisdiction: the server rejects the repeated id instead
    const [jurisdictionId] = useState(() => crypto.randomUUID());

    const [formData, setFormData] = useState({
        name: "",
        info: "",
    });
    const [errorMessage, setErrorMessage] = useState("");
    const [alreadyCreated, setAlreadyCreated] = useState(false);
    const [submitting, setSubmitting] = useState(false);

    const handleChange : React.ChangeEventHandler<HTMLInputElement> = (event : React.ChangeEvent<HTMLInputElement>) => {
        let val : string | boolean = event.target.value
        if (event.target.type === "checkbox") {
            val = event.target.checked
        }
        setFormData({ ...formData, [event.target.name]: val})
    }

    // permissions check (for now)
    const formDisabled = function() : boolean {
        return !isGlobalAdmin(user)
    }

    const submitForm = function(event : React.FormEvent<HTMLFormElement>) {
        event.preventDefault()

        setErrorMessage("")
        setAlreadyCreated(false)

        const form = event.currentTarget;
        if (form.checkValidity() === false) {
            return
        }

        // disable the form until the request finishes, so it can't be sent again in the meantime
        setSubmitting(true)

        // create the jurisdiction
        createJurisdiction(jurisdictionId, formData.name, formData.info).then(resp => {
            setSubmitting(false)

            if (resp == null) {
                setErrorMessage("Error connecting to server to create jurisdiction")
                return
            }

            if (resp.status_code == 409) {
                // the id or the name is taken. the id is only generated once per form, so if a
                // jurisdiction has it, an earlier attempt went through
                getJurisdiction(jurisdictionId).then(existing => {
                    if (existing != null && existing.status_code == 200) {
                        setAlreadyCreated(true)
                    } else {
                        setErrorMessage("A jurisdiction named \"" + formData.name + "\" already exists")
                    }
                })
                return
            }
            if (resp.status_code == 401) {
                setErrorMessage("Unauthorized to create jurisdiction")
                return
            }
            if (resp.status_code != 200) {
                setErrorMessage("Unknown server error (status " + resp.status_code + ")")
                return
            }

            if (resp.jurisdiction_id != "") {
                navigate("/jurisdictions/" + resp.jurisdiction_id)
            }
        }).catch(error => {
            // createJurisdiction throws if it can't build the request, e.g. if the user's key can't
            // be loaded or used to sign it
            console.log("error preparing jurisdiction request", error)
            setSubmitting(false)
            setErrorMessage("Error preparing the request to create jurisdiction")
        })
    }

    useEffect(() => {
        // fetch the user for the current session
        getUser().then(setUser)

        // no cleanup necessary
        return () => {};
    }, [])

    return (
        <div className="container">
            <h2 className="text-center">
                Create a Jurisdiction
            </h2>
            <Form className="" onSubmit={submitForm}>
                <fieldset disabled={formDisabled() || submitting}>
                <Form.Group className="mb-3" controlId="formName">
                    <Form.Label>Name</Form.Label>
                    <Form.Control
                        required
                        type="text"
                        placeholder="Enter name"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                    />
                </Form.Group>
                <Form.Group className="mb-3" controlId="formInfo">
                    <Form.Label>Info</Form.Label>
                    <Form.Control
                        required
                        type="text"
                        placeholder="Enter info"
                        name="info"
                        value={formData.info}
                        onChange={handleChange}
                    />
                </Form.Group>
                <Button variant="primary" type="submit">
                    {submitting ? "Creating..." : "Create"}
                </Button>
                </fieldset>
            </Form>
            <Alert variant="info" className="mt-3" show={alreadyCreated}>
                This jurisdiction was already created by an earlier attempt, so changes made since then
                weren&apos;t saved. <Link to={"/jurisdictions/" + jurisdictionId} className="alert-link">View the jurisdiction</Link>
            </Alert>
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
