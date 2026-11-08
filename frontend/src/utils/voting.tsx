import { User } from "@/models/user";
import { Election } from "@/services/electionservice";
import { castVote, CREATE_RECOVERY_RECORD_ACTION, createRecoveryRecord, getRecoveryRecord, requestBlindSignature } from "@/services/voteservice";
import { checkElectionKey } from "@/utils/audit";
import { SignedRequest, verifyOwnSignedRequest } from "@/utils/auth";
import { Ballot, buildVote, decryptBallot, encryptBallot, finalizeBallot, prepareBallot, voteCandidate } from "@/utils/ballot";
import { publicKeyHash } from "@/utils/keys";
import { getRoot } from "@/utils/root";

// VoteError is an error with a message to show the voter
export class VoteError extends Error {}

// messageFor returns the message to show the voter for an error while voting
export function messageFor(error : unknown) : string {
    if (error instanceof VoteError) {
        return error.message
    }

    console.log("error while voting", error)
    return "Error preparing your vote"
}

// openRecoveryRecord checks that the user uploaded the recovery record for the election, then
// decrypts its ballot
export async function openRecoveryRecord(user : User, election : Election, signed_request : SignedRequest) : Promise<Ballot> {
    let uploaded_by_user = false
    try {
        uploaded_by_user = signed_request.action == CREATE_RECOVERY_RECORD_ACTION
            && JSON.parse(signed_request.body).election_id == election.id
            && await verifyOwnSignedRequest(signed_request)
    } catch (error) {
        console.log("error checking the signature on the recovery record", error)
    }
    if (!uploaded_by_user) {
        throw new VoteError("The server's copy of your saved vote wasn't uploaded by you, so it may have been altered. Contact the election's administrators.")
    }

    let ballot : Ballot
    try {
        ballot = await decryptBallot(user.aes_key as CryptoKey, JSON.parse(signed_request.body).encrypted_record)
    } catch (error) {
        console.log("error decrypting the recovery record", error)
        throw new VoteError("Your saved vote couldn't be decrypted. You uploaded it, so the device you started voting on may have saved it incorrectly.")
    }
    if (voteCandidate(ballot, election.id) == null) {
        throw new VoteError("Your saved vote isn't for this election.")
    }

    return ballot
}

// loadBallot fetches and opens the user's recovery record for the election. It resolves to null if
// they haven't started voting.
export async function loadBallot(user : User, election : Election) : Promise<Ballot|null> {
    const resp = await getRecoveryRecord(election.id)
    if (resp == null) {
        throw new VoteError("Error connecting to server to check for your saved vote")
    }
    if (resp.status_code == 404) {
        return null
    }
    if (resp.status_code == 401) {
        throw new VoteError("You aren't authorized to vote in this election")
    }
    if (resp.status_code != 200 || resp.signed_request == null) {
        throw new VoteError("Unknown server error (status " + resp.status_code + ")")
    }

    return await openRecoveryRecord(user, election, resp.signed_request)
}

// startBallot prepares a vote for the candidate and saves it as the user's recovery record, which
// fixes their choice
async function startBallot(user : User, election : Election, election_key : CryptoKey, candidate_id : string) : Promise<Ballot> {
    const ballot : Ballot = await prepareBallot(election_key, buildVote(election.id, candidate_id))
    const encrypted_record : string = await encryptBallot(user.aes_key as CryptoKey, ballot)

    // voters are authorized in the election's jurisdiction
    const resp = await createRecoveryRecord(election.id, election.jurisdiction_id, encrypted_record)
    if (resp == null) {
        throw new VoteError("Error connecting to server to save your vote")
    }
    if (resp.status_code == 409) {
        // trying again picks up the vote that was saved first
        throw new VoteError("A vote was already saved for you, maybe from another device. Try again to finish casting it.")
    }
    if (resp.status_code == 403) {
        throw new VoteError("This election isn't open for voting")
    }
    if (resp.status_code == 401) {
        throw new VoteError("You aren't authorized to vote in this election")
    }
    if (resp.status_code != 201 && resp.status_code != 200) {
        throw new VoteError("Unknown server error (status " + resp.status_code + ")")
    }

    return ballot
}

// castBallot runs every step of casting the user's vote that hasn't happened yet. Every step can be
// repeated safely, so after a failure it just runs again from the start. choice is the candidate the
// voter chose, or null to finish casting the vote they already saved. onStep reports progress, and
// onBallot reports the voter's saved ballot once there is one, since it fixes their choice.
export async function castBallot(user : User, election : Election, choice : string|null, onStep : (step : string) => void, onBallot : (ballot : Ballot) => void) : Promise<void> {
    onStep("Checking the election key")
    let election_key : CryptoKey
    let key_hash : string
    try {
        election_key = await checkElectionKey(election, await getRoot())
        key_hash = await publicKeyHash(election.public_key)
    } catch (error) {
        console.log("election key check failed", error)
        throw new VoteError("The election's key couldn't be confirmed, so it isn't safe to vote with it. Try again, and if it keeps happening, contact the election's administrators.")
    }

    onStep("Checking for a saved vote")
    let ballot : Ballot|null = await loadBallot(user, election)
    if (ballot != null) {
        onBallot(ballot)
        // a vote saved by an earlier attempt, maybe on another device, is the only one that can be
        // cast, so the voter sees which candidate it is for before it is
        if (choice != null && voteCandidate(ballot, election.id) != choice) {
            throw new VoteError("A vote for a different candidate was already saved for you, so that is the vote you can finish casting.")
        }
    } else {
        if (choice == null) {
            throw new VoteError("Choose a candidate to vote for")
        }

        onStep("Saving your vote")
        ballot = await startBallot(user, election, election_key, choice)
        onBallot(ballot)
    }

    onStep("Getting your vote signed")
    const signature_resp = await requestBlindSignature(election.id, election.jurisdiction_id, ballot.blinded_message, key_hash)
    if (signature_resp == null) {
        throw new VoteError("Error connecting to server to get your vote signed")
    }
    if (signature_resp.status_code == 403) {
        throw new VoteError("This election isn't open for voting")
    }
    if (signature_resp.status_code == 401) {
        throw new VoteError("You aren't authorized to vote in this election")
    }
    if (signature_resp.status_code == 409) {
        throw new VoteError("A different vote was already signed for you in this election.")
    }
    if (signature_resp.status_code == 400) {
        throw new VoteError("The server rejected the request to sign your vote")
    }
    if (signature_resp.status_code != 201 && signature_resp.status_code != 200) {
        throw new VoteError("Unknown server error (status " + signature_resp.status_code + ")")
    }

    onStep("Checking the signature")
    let signature : string
    try {
        signature = await finalizeBallot(election_key, ballot, signature_resp.blind_signature)
    } catch (error) {
        console.log("error unblinding the signature", error)
        throw new VoteError("The server's signature on your vote isn't valid, so your vote wasn't cast. Try again, and contact the election's administrators if it keeps happening.")
    }

    onStep("Casting your vote")
    const cast_resp = await castVote(election.id, ballot.nonce, ballot.vote, signature)
    if (cast_resp == null) {
        throw new VoteError("Error connecting to server to cast your vote")
    }
    if (cast_resp.status_code == 403) {
        throw new VoteError("This election closed before your vote was cast")
    }
    if (cast_resp.status_code == 409) {
        throw new VoteError("A different vote was already cast with your vote's nonce.")
    }
    if (cast_resp.status_code == 400) {
        throw new VoteError("The server rejected your vote")
    }
    if (cast_resp.status_code != 201 && cast_resp.status_code != 200) {
        throw new VoteError("Unknown server error (status " + cast_resp.status_code + ")")
    }
}
