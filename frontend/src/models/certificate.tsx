export enum CertificateRole {
    global_admin = "global_admin",
	system = "system",
	jurisdiction_admin = "jurisdiction_admin",
	registrar = "registrar",
	voter = "voter",
    unassigned = "",
};

export class SimpleCertificate {
    cert_pem : string = "";
    id : string = '';
    jurisdiction_id : string | null = null;
    role : CertificateRole = CertificateRole.unassigned;
};

