import { useState } from "react";
import React from "react";
import { Link, useNavigate } from "react-router-dom"
import { register } from "../services/authservice";
import { Button, Form } from "react-bootstrap";

const taken_username_message = "This username is taken. Please select another.";
const unknown_error_message = "Unknown error. Please try again later."

export default function RegistrationPage() : React.JSX.Element {
    const navigate = useNavigate();

    const [formData, setFormData] = useState({
        username: "",
        password: "",
        registration_token: "",
        remember_me: false,
    })

    const [invalidMessage, setInvalidMessage] = useState("");
    
    const handleChange : React.ChangeEventHandler<HTMLInputElement> = (event : React.ChangeEvent<HTMLInputElement>) => {
        let val : string | boolean = event.target.value
        if (event.target.type === "checkbox") {
            val = event.target.checked
        }
        setFormData({ ...formData, [event.target.name]: val})
    }

    const handleSubmit : React.FormEventHandler<HTMLFormElement> = function(event : React.FormEvent<HTMLFormElement>) {
        event.preventDefault()
        event.stopPropagation();

        setInvalidMessage("");

        const form = event.currentTarget;
        if (form.checkValidity() === false) {
            return
        }

        register(formData.username, formData.password, formData.registration_token, formData.remember_me).then(register_response => {
            if (register_response.success) {
                navigate("/");
                return;
            }

            switch(register_response.status_code) {
                case 409: {
                    setInvalidMessage(taken_username_message);
                    break;
                }
                default: {
                    setInvalidMessage(unknown_error_message);
                    break;
                }
            }
        });
    }

    return (
        <div>
            <div className="container">
                <h2 className="text-center">Register</h2>
                <Form noValidate className="" onSubmit={handleSubmit}>
                    <Form.Group className="mb-3" controlId="formUsername">
                    <Form.Label>Username</Form.Label>
                    <Form.Control
                        required
                        type="text"
                        placeholder="Enter username"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        isInvalid={invalidMessage !== ""}
                    />
                    <Form.Control.Feedback type="invalid">
                        {invalidMessage}
                    </Form.Control.Feedback>
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formPassword">
                    <Form.Label>Password</Form.Label>
                    <Form.Control
                        required
                        type="password"
                        placeholder="Password"
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                    />
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formPassword">
                    <Form.Label>Registration Token (not required)</Form.Label>
                    <Form.Control
                        type="text"
                        placeholder="Registration token"
                        name="registration_token"
                        value={formData.registration_token}
                        onChange={handleChange}
                    />
                    </Form.Group>
                    <Form.Group className="mb-3" controlId="formRememberMe">
                        <Form.Check
                            type="checkbox"
                            label="Remember Me"
                            name="remember_me"
                            checked={formData.remember_me}
                            onChange={handleChange} />
                    </Form.Group>
                    <Button className="container-fluid" variant="primary" type="submit">
                        Register
                    </Button>
                </Form>
                <div>
                    Already have an account? <Link to={"/login"}>Log In</Link>
                </div>
            </div>
        </div>
    );
}