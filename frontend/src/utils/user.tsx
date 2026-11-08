import { exportAESKey, exportPrivateKey, importAESKey, importECDSAPrivateKey } from "./keys"
import { User, SimpleUser } from '@/models/user';
import { CertificateRole } from '@/models/certificate';

let user_obj : User | null;

export async function userToSimpleUser(user: User) : Promise<SimpleUser> {
    const simple_user : SimpleUser = {
        username: user.username,
        public_key: user.public_key,
        private_key: await exportPrivateKey(user.private_key as CryptoKey),
        aes_key: await exportAESKey(user.aes_key as CryptoKey),
        remember_me: user.remember_me,
        certificates: user.certificates,
    }

    return simple_user;
}

export async function saveUser(user : User) {
    user_obj = user;
    sessionStorage.removeItem("user")
    localStorage.removeItem("user")

    const simple_user = await userToSimpleUser(user)

    if (user.remember_me) {
        localStorage.setItem("user", JSON.stringify(simple_user))
    } else {
        sessionStorage.setItem("user", JSON.stringify(simple_user))
    }
}

export async function simpleUserToUser(simple_user : SimpleUser) : Promise<User> {
    const aes_key : CryptoKey = await importAESKey(simple_user.aes_key);

    const private_key : CryptoKey = await importECDSAPrivateKey(simple_user.private_key)

    return {
        username: simple_user.username,
        public_key: simple_user.public_key,
        private_key,
        aes_key,
        remember_me: simple_user.remember_me,
        certificates: simple_user.certificates,
    }
}

export async function getUser() : Promise<User | null> {
    if (user_obj != null) {
        return user_obj;
    }
    let json : string | null = sessionStorage.getItem("user")
    if (json === null) {
        json = localStorage.getItem("user")
    }

    if (json === null) {
        return null
    }

    const simple_user : SimpleUser = JSON.parse(json)

    return await simpleUserToUser(simple_user);
}

export function isGlobalAdmin(user : User | null) : boolean {
    if (user == null || user.certificates == null) {
        return false
    }

    return user.certificates.some(cert => cert.role == CertificateRole.global_admin)
}

// isVoterIn reports whether the user is authorized to vote in the jurisdiction's elections
export function isVoterIn(user : User | null, jurisdiction_id : string) : boolean {
    if (user == null || user.certificates == null) {
        return false
    }

    return user.certificates.some(cert => cert.role == CertificateRole.voter && cert.jurisdiction_id == jurisdiction_id)
}

export function logout() : Promise<[void, void]> {
    user_obj = null;
    return Promise.all([localStorage.removeItem("user"), sessionStorage.removeItem("user")]);
}