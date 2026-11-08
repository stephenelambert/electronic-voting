# Registration

Registration is the process by which a user sets up an account.

## Preconditions
- A user can register for an account any time once the first global admin has registered.
- Only a username and password are required.
- The username must not be taken.
- The sign-up page shows the fingerprint of the instance's anchor, the first global admin's key, for the user to compare with the one the instance's operator publishes, and the account pins it (see Pinning the Anchor in the [design](../design.md)).

### Exceptions
The only time a user can "register" with a taken username is for a user that has been created by the system but not registered yet (such as the first global admin). They have to give the account's setup token as their registration token (see Admin Setup in the [MVP doc](../mvp.md)).
The first global admin pins their own key, since it's the anchor.
All user accounts must have a password associated with them.

## Next Steps
After creating an account, users must wait until they are authorized for voting or other roles by an administrator or a registrar.