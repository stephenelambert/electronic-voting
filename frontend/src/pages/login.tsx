import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { login } from "@/services/authservice";
import { Button, Form } from "react-bootstrap";

const invalid_credential_message = "Invalid username and/or password. Please try again."
const recommend_register_page_message = "Registration incomplete. Please go to the registration page."
const unknown_error_message = "Unknown error. Please try again later."
const key_mismatch_message = "The server's copy of your public key doesn't match your private key, so it isn't safe to log in. Contact the server's administrators."

export default function LoginPage() {
    const navigate = useNavigate();

    const [formData, setFormData] = useState({
        username: "",
        password: "",
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

    const handleSubmit : React.FormEventHandler<HTMLFormElement> = (event : React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        event.stopPropagation();

        setInvalidMessage("");
        
        const form = event.currentTarget;
        if (form.checkValidity() === false) {
            return
        }

        login(formData.username, formData.password, formData.remember_me).then(login_response => {
            if (login_response.success) {
                navigate("/")
                return
            }
            if (login_response.key_mismatch) {
                setInvalidMessage(key_mismatch_message);
                return
            }

            switch(login_response.status_code) {
                case 401: {
                    setInvalidMessage(invalid_credential_message);
                    break;
                }
                case 403: {
                    setInvalidMessage(recommend_register_page_message);
                    break;
                }
                default: {
                    setInvalidMessage(unknown_error_message);
                    break;
                }
            }
        })
    }

    return (
        <div>
            <div className="container">
                <h2 className="text-center">Log In</h2>
                <Form noValidate className="" onSubmit={handleSubmit}>
                    <Form.Group className="mb-3" controlId="formUsername">
                        <Form.Label>Username</Form.Label>
                        <Form.Control
                            required
                            type="text"
                            placeholder="Enter username"
                            name="username"
                            value={formData.username}
                            onChange={handleChange} />
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
                            isInvalid={invalidMessage !== ''} />
                        <Form.Control.Feedback type="invalid">
                            {invalidMessage}
                        </Form.Control.Feedback>
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
                        Log In
                    </Button>
                </Form>
                <div className="">
                    Don&apos;t have an account? <Link to={'/register'}>Register here.</Link>
                </div>
            </div>
        </div>
    );
}