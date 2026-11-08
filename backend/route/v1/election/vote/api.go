package vote

import (
	"context"
	"electronic-voting/database"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// maxEncryptedRecordLength is the longest encrypted recovery record accepted, in base64 characters.
// Records are about 1,300.
const maxEncryptedRecordLength = 4096

// electionJurisdiction returns the jurisdiction of the election in the context, which voters must
// be authorized in
func electionJurisdiction(r *http.Request) *string {
	election := r.Context().Value(ctxkey.Key("election")).(model.Election)
	return &election.JurisdictionID
}

// isOpen reports whether votes can be cast in the election at now, a Unix timestamp in seconds
func isOpen(election model.Election, now int64) bool {
	return election.TimeOpen <= now && now < election.TimeClose
}

// recoveryRecordToCtx adds the authenticated account's recovery record for the election in the
// context to the context. The account only needs to be authenticated, not currently authorized to
// vote.
func recoveryRecordToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		account := ctx.Value(ctxkey.Key("account")).(*model.Account)

		record := model.VoteRecoveryRecord{
			ElectionID: election.ID,
			AccountID:  account.ID,
		}
		found, err := record.FindByElectionAndAccount(ctx, tx)
		if err != nil {
			log.Printf("error querying for vote recovery record: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("recovery_record"), record)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// createRecoveryRecord stores the authenticated voter's recovery record for the election in the
// context, as the signed request that uploads it. Records can't be replaced, since a signature may
// already have been issued for one, but a client that lost the response to its upload can send the
// same body again: alreadyCreated is served for it instead of created.
func createRecoveryRecord(created, alreadyCreated http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		account := ctx.Value(ctxkey.Key("account")).(*model.AccountWithOneCertificate)
		signedRequest := ctx.Value(ctxkey.Key("signed_request")).(model.SignedRequest)
		req := ctx.Value(ctxkey.Key("dto")).(*recoveryRecordRequest)

		// the signed request says which election the record is for, so it has to be this one
		if req.ElectionID != election.ID {
			log.Print("vote recovery record is for a different election")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		now := time.Now().Unix()
		if !isOpen(election, now) {
			log.Printf("election %s isn't open for vote recovery records", election.ID)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// the server can't read the record, so only its size and encoding are checked
		if len(req.EncryptedRecord) > maxEncryptedRecordLength {
			log.Print("encrypted vote recovery record is too long")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, err := localcrypto.DecodeBase64(req.EncryptedRecord); err != nil {
			log.Printf("invalid encrypted vote recovery record: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		existing := model.VoteRecoveryRecord{
			ElectionID: election.ID,
			AccountID:  account.ID,
		}
		found, err := existing.FindByElectionAndAccount(ctx, tx)
		if err != nil {
			log.Printf("error querying for existing vote recovery record: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if found {
			if existing.SignedRequest.Body != signedRequest.Body {
				log.Printf("account %s already has a different vote recovery record for election %s", account.ID, election.ID)
				w.WriteHeader(http.StatusConflict)
				return
			}

			ctx = context.WithValue(ctx, ctxkey.Key("recovery_record"), existing)
			alreadyCreated.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		record := model.VoteRecoveryRecord{
			ElectionID:       election.ID,
			AccountID:        account.ID,
			SignedRequest:    signedRequest,
			CreatedTimestamp: now,
		}
		err = record.DBInsert(ctx, tx)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			// another upload for the account committed first
			log.Printf("account %s uploaded another vote recovery record for election %s at the same time", account.ID, election.ID)
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error inserting vote recovery record: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("recovery_record"), record)
		created.ServeHTTP(w, r.WithContext(ctx))
	})
}

// blindSign signs the blinded vote in the request with the key of the election in the context, for
// the authenticated voter. Each voter gets one blinded vote signed per election: sending the same one
// again serves alreadySigned instead of signed, with the stored signature, and a different one is
// rejected.
func blindSign(signed, alreadySigned http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		account := ctx.Value(ctxkey.Key("account")).(*model.AccountWithOneCertificate)
		signedRequest := ctx.Value(ctxkey.Key("signed_request")).(model.SignedRequest)
		req := ctx.Value(ctxkey.Key("dto")).(*blindSignatureRequest)

		// the signed request says which election the vote is for, so it has to be this one
		if req.ElectionID != election.ID {
			log.Print("blind signature request is for a different election")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		now := time.Now().Unix()
		if !isOpen(election, now) {
			log.Printf("election %s isn't open for blind signatures", election.ID)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// the request names the key the voter blinded under, so a server that gave the voter a
		// different key would leave signed evidence of it
		keyHash, err := localcrypto.PublicKeyHash(election.PublicKey)
		if err != nil {
			log.Printf("error hashing election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if req.PublicKeyHash != keyHash {
			log.Print("blind signature request names a key other than the election's")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// stored as sent, so it has to be in the one encoding repeated requests are compared in
		blindedMessage, err := localcrypto.DecodeBase64(req.BlindedMessage)
		if err != nil {
			log.Printf("invalid blinded message: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		existing := model.BlindSignedVote{
			ElectionID: election.ID,
			AccountID:  account.ID,
		}
		found, err := existing.FindByElectionAndAccount(ctx, tx)
		if err != nil {
			log.Printf("error querying for existing blind signed vote: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if found {
			if existing.BlindedMessage != req.BlindedMessage {
				log.Printf("account %s already has a different vote signed in election %s", account.ID, election.ID)
				w.WriteHeader(http.StatusConflict)
				return
			}

			ctx = context.WithValue(ctx, ctxkey.Key("blind_signed_vote"), existing)
			alreadySigned.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		signingKey := model.SigningKey{
			PublicKey: election.PublicKey,
		}
		found, err = signingKey.FindByPublicKey(ctx, tx)
		if err != nil {
			log.Printf("error querying for election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !found {
			log.Printf("key for election %s not found", election.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		privateKey, err := localcrypto.ParseElectionPrivateKey(string(signingKey.PrivateKey))
		if err != nil {
			log.Printf("error loading election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		blindSignature, err := localcrypto.BlindSign(privateKey, blindedMessage)
		if errors.Is(err, localcrypto.ErrInvalidBlindedMessage) {
			log.Printf("invalid blinded message: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		} else if err != nil {
			log.Printf("error signing blinded vote: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		vote := model.BlindSignedVote{
			ElectionID:       election.ID,
			AccountID:        account.ID,
			BlindedMessage:   req.BlindedMessage,
			SignedRequest:    signedRequest,
			BlindSignature:   base64.StdEncoding.EncodeToString(blindSignature),
			CreatedTimestamp: now,
		}
		err = vote.DBInsert(ctx, tx)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			// another request for the account committed first
			log.Printf("account %s had another vote signed in election %s at the same time", account.ID, election.ID)
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error inserting blind signed vote: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("blind_signed_vote"), vote)
		signed.ServeHTTP(w, r.WithContext(ctx))
	})
}

// cast stores a vote in the election in the context. Votes aren't authenticated, so casting one
// isn't directly tied to the voter's account, though the server can link the two through the
// authenticated requests around it, like the one for the blind signature. Nothing identifying a
// vote is logged. A vote in the one valid format for the election is stored even if its candidate
// isn't on the ballot, since the tally counts each candidate ID that votes name. Sending a vote
// that is already stored serves alreadyStored instead of stored, so a client that doesn't know
// whether its vote arrived can send it again.
func cast(stored, alreadyStored http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		req := ctx.Value(ctxkey.Key("dto")).(*castRequest)

		vote, err := localcrypto.ParseVote(req.Vote)
		if err != nil {
			log.Printf("invalid vote: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if vote.ElectionID != election.ID {
			log.Print("vote is for a different election")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		nonce, err := localcrypto.DecodeNonce(req.Nonce)
		if err != nil {
			log.Printf("invalid vote nonce: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// stored as sent, so it has to be in the one encoding repeated votes are compared in
		signature, err := localcrypto.DecodeBase64(req.Signature)
		if err != nil {
			log.Printf("invalid vote signature: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		publicKey, err := localcrypto.ParseElectionPublicKey(election.PublicKey)
		if err != nil {
			log.Printf("error loading election key: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err = localcrypto.VerifyVote(publicKey, nonce, []byte(req.Vote), signature); err != nil {
			log.Printf("invalid vote: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		existing := model.Vote{
			ElectionID: election.ID,
			Nonce:      req.Nonce,
		}
		found, err := existing.FindByElectionAndNonce(ctx, tx)
		if err != nil {
			log.Printf("error querying for existing vote: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if found {
			if existing.Raw != req.Vote || existing.Signature != req.Signature {
				log.Print("a different vote was already cast with the vote's nonce")
				w.WriteHeader(http.StatusConflict)
				return
			}

			alreadyStored.ServeHTTP(w, r)
			return
		}

		// counted just before the vote is inserted, since the counter's row stays locked until the
		// vote commits. Whether the election is open is checked here, after looking for the vote, so
		// a client that sends its vote again after the election closes still learns that it was
		// stored
		counter := model.ElectionVoteCounter{
			ElectionID: election.ID,
		}
		open, err := counter.Increment(ctx, tx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// the database's clock decides whether the election is open, rather than this server's,
		// since the clocks of several API servers can disagree. A final counter's votes may already
		// be published, so no more can be counted. The 403 rolls back the increment
		if !open {
			log.Printf("election %s isn't open for votes", election.ID)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if counter.Final {
			log.Printf("votes in election %s are final", election.ID)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		record := model.Vote{
			ElectionID:  election.ID,
			Nonce:       req.Nonce,
			Raw:         req.Vote,
			CandidateID: vote.CandidateID,
			Signature:   req.Signature,
		}
		err = record.DBInsert(ctx, tx)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			// the same vote was sent again, and the other request committed first
			log.Print("vote was cast by another request at the same time")
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error inserting vote: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		stored.ServeHTTP(w, r)
	})
}
