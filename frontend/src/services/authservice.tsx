import { arrayBufferToBase64, base64ToArrayBuffer } from "../utils/base64";
import { checkOwnPublicKey, encryptWithAES, decryptWithAES, exportAESKey, exportPrivateKey, exportPublicKey, keyFromExportKey, makeECDSA } from "../utils/keys";
import { KEY_STRETCHING, identifiers, loadOpaque, normalizeUsername, passwordInput } from "../utils/opaque";
import axios from "axios";
import { saveUser, simpleUserToUser } from "../utils/user";
import { User, SimpleUser } from "@/models/user";
import { SimpleCertificate } from "models/certificate";

export class LoginResponse {
    status_code: number = 200;
    success: boolean = false;
    // key_mismatch is set if the server sent a public key that isn't the user's (see checkOwnPublicKey)
    key_mismatch: boolean = false;
};

interface UserResponse {
    private_key: string;
    public_key: string;
    aes_key: string;
    certificates: SimpleCertificate[];
}

// login logs in with OPAQUE (see utils/opaque): the API answers the client's first message, and only
// hands over the account's encrypted keys once the client's second message shows it knows the
// password. The password itself is never sent.
export async function login(username : string, password : string, remember_me : boolean) : Promise<LoginResponse> {
    username = normalizeUsername(username)
    const password_input : string = passwordInput(username, password)

    const login_response : LoginResponse = new LoginResponse();

    let user_obj : UserResponse;
    let export_key : string;
    try {
        const opaque = await loadOpaque()
        const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: password_input })

        const start_response = await axios.post("/api/v1/login/start", {
            username,
            ke1: startLoginRequest,
        });

        login_response.status_code = start_response.status;

        if (start_response.status != 200) {
            return login_response;
        }

        // this fails if the password is wrong, and then nothing more is sent
        const finished = opaque.client.finishLogin({
            clientLoginState,
            loginResponse: start_response.data.ke2,
            password: password_input,
            keyStretching: KEY_STRETCHING,
            identifiers: identifiers(username),
        })
        if (finished === undefined) {
            login_response.status_code = 401;
            return login_response;
        }
        export_key = finished.exportKey

        const response = await axios.put("/api/v1/login", {
            login_id: start_response.data.login_id,
            ke3: finished.finishLoginRequest,
        });

        login_response.status_code = response.status;

        if (response.status != 200) {
            return login_response;
        }

        user_obj = response["data"]
    } catch (error) {
        console.log("Error", error)

        login_response.success = false;
        return login_response;
    }

    const pass_key : CryptoKey = await keyFromExportKey(export_key);

    const aes_key_bits : Uint8Array = new Uint8Array(await decryptWithAES(pass_key, new Uint8Array(base64ToArrayBuffer(user_obj.aes_key))))
    const aes_key : CryptoKey = await crypto.subtle.importKey("raw", aes_key_bits,
    {
        name: "AES-GCM"
    }, true,
    ["encrypt", "decrypt"])

    const private_key_str : string = new TextDecoder().decode(await decryptWithAES(aes_key, new Uint8Array(base64ToArrayBuffer(user_obj.private_key))))

    const simple_user : SimpleUser = {
        username,
        public_key: user_obj.public_key,
        private_key: private_key_str,
        aes_key: await exportAESKey(aes_key),
        remember_me,
        certificates: user_obj.certificates,
    }

    const user : User = await simpleUserToUser(simple_user)

    // the server sends the public key, so it has to be the private key's before it's trusted as the
    // user's own, like when checking the signature on a vote recovery record
    try {
        await checkOwnPublicKey(user.private_key as CryptoKey, user.public_key)
    } catch (error) {
        console.log("public key check failed", error)

        login_response.key_mismatch = true;
        return login_response;
    }

    await saveUser(user)

    login_response.success = true
    return login_response;
}

export class RegisterResponse {
    status_code: number = 200;
    success: boolean = false;
};

// register registers with OPAQUE (see utils/opaque), and uploads the account's keys, encrypted under
// a key only this client can derive from the password. The password itself is never sent.
// registration_token claims an admin account the API created, as its setup token.
export async function register(username : string, password : string, registration_token : string, remember_me : boolean) : Promise<RegisterResponse> {
    username = normalizeUsername(username)
    const password_input : string = passwordInput(username, password)

    const text_encoder : TextEncoder = new TextEncoder()

    const register_response : RegisterResponse = new RegisterResponse();

    let registration_record : string;
    let export_key : string;
    try {
        const opaque = await loadOpaque()
        const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: password_input })

        const start_response = await axios.post("/api/v1/register/start", {
            username,
            registration_request: registrationRequest,
        })

        register_response.status_code = start_response.status;

        if (start_response.status != 200) {
            return register_response;
        }

        const finished = opaque.client.finishRegistration({
            clientRegistrationState,
            registrationResponse: start_response.data.registration_response,
            password: password_input,
            keyStretching: KEY_STRETCHING,
            identifiers: identifiers(username),
        })
        registration_record = finished.registrationRecord
        export_key = finished.exportKey
    } catch (error) {
        console.log("Error", error)

        register_response.success = false;
        return register_response;
    }

    const pass_key : CryptoKey = await keyFromExportKey(export_key)

    // make aes_key
    const aes_key_bits : Uint8Array = crypto.getRandomValues(new Uint8Array(32))
    const aes_key : CryptoKey = await crypto.subtle.importKey("raw", aes_key_bits,
    {
        name: "AES-GCM"
    }, true,
    ["encrypt", "decrypt"])

    // generate private key
    const key_pair : CryptoKeyPair = await makeECDSA()
    const private_key : CryptoKey = key_pair.privateKey
    const encoded_private_key : string = await exportPrivateKey(private_key)

    const public_key : CryptoKey = key_pair.publicKey
    const encoded_public_key : string = await exportPublicKey(public_key)

    const user = {
        username,
        registration_record,
        public_key: encoded_public_key,
        private_key: arrayBufferToBase64((await encryptWithAES(aes_key, text_encoder.encode(encoded_private_key))).buffer),
        registration_token,
        aes_key: arrayBufferToBase64((await encryptWithAES(pass_key, aes_key_bits)).buffer)
    }

    let user_obj : UserResponse;
    try {
        const response = await axios.post("/api/v1/register", user)

        register_response.status_code = response.status;

        if (response.status != 200) {
            return register_response;
        }

        user_obj = response["data"]
    }catch(error) {
        console.log("Error", error)

        register_response.success = false;
        return register_response;
    }

    await saveUser({
        username,
        public_key: encoded_public_key,
        private_key,
        aes_key,
        remember_me,
        certificates: user_obj.certificates,
    });

    register_response.success = true;
    return register_response;
}
