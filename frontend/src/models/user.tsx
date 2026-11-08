import { SimpleCertificate } from "./certificate";

export class User {
    username : string = "";
    public_key : string = "";
    private_key : CryptoKey | null = null;
    aes_key : CryptoKey | null = null;
    remember_me : boolean = false;
    certificates: SimpleCertificate[] | null = null;
}

export class SimpleUser {
    username : string = "";
    public_key : string = "";
    private_key : string = "";
    aes_key : string = "";
    remember_me : boolean = false;
    certificates: SimpleCertificate[] | null = null;
}