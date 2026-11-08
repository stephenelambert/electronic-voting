# Pages
This directory covers the pages necessary for the application to work.
Most pages will have an authenticated variant and an unauthenticated variant, as most data will be at least viewable without user authentication.

Pages that check signed records check them against the pinned anchor (see Pinning the Anchor in the [main design document](../design.md)). A visitor who isn't logged in and hasn't pinned it in their browser sees a warning with the anchor's fingerprint, and a button to pin it.

## Homepage
The homepage will contain information about current (active) elections, recently finished elections, and upcoming elections.
Each election will have a link to go into a view specifically for that election.

Links will be included to view all jurisdictions and elections.

### Unauthenticated Homepage
The unauthenticated homepage will show elections for top-level jurisdictions.

### Authenticated Homepage
The authenticated homepage will default to show elections for jurisdictions and parent jurisdictions for which the authenticated user can vote.
Elections for other jurisdictions will likely be found lower on the page.

## Sign In/Sign Up Page (Unauthenticated Only)
The Sign In page and Sign Up page are used for users to sign in or sign up for an account for the service.
The Sign Up page shows the fingerprint of the instance's anchor, the first global admin's key, for the user to compare with the one the instance's operator publishes, and the new account pins it (see Pinning the Anchor in the [main design document](../design.md)). Nobody can sign up until the first global admin has.

## All Jurisdictions Page
The All Jurisdictions page will list all top-level jurisdictions and link to their respective pages.

### Authenticated
If a user is authenticated as a global admin, a button will be shown that will bring up a modal to create a jurisdiction.

## Jurisdiction Page
The Jurisdiction page will show information about a specific jurisdiction.
The page will include links for the parent jurisdiction (if applicable) and any child jurisdictions (if applicable).
The page will include links to all active elections, recent elections, and upcoming elections for the jurisdiction, as well as separate links for past elections.
This page will also include the number of authorized voters for the jurisdiction (including sub-jurisdictions).

The Jurisdiction page has an Audit button for anyone, which checks the request that created the jurisdiction and shows the fingerprints of the admin's key and the root's. It can also count the jurisdiction's voters, which downloads every voter authorization (see What Browsers Check, under Auditing the System in the [main design document](../design.md)).
Later, the audit will also cover the jurisdiction's changes since it was created.

### Authenticated Jurisdiction Page (Voter)
Voters in a jurisdiction (or in a child jurisdiction) will be able to view the admins and registrars for that jurisdiction.
Voters see the same Audit button as everyone else. Once jurisdictions can be changed, it will also show a history of the changes.

### Authenticated Jurisdiction Page (Registrar Role)
Users with the Registrar role for a jurisdiction (or parent jurisdiction) will have a button and modal to add users to the jurisdiction (with multiple confirmations for adding users to non-leaf jurisdictions).
They will also have a link to view users (admins, registrars, and voters) for the jurisdiction (and child jurisdictions).

### Authenticated Jurisdiction Page (Admin Role)
Jurisdiction and higher admins will have the same view and options as Registrars.
They will also have the option to modify the jurisdiction, as well as create a child jurisdiction or election, or add another admin or registrar.

## Jurisdiction Users Page (Authenticated Admin or Registrar)
This page will have separate sections for Jurisdiction Admins, registrars, and voters, all for this jurisdiction and potentially for lower jurisdictions.
A filter will be available to show deauthorized users as well (it will be off by default).
Admins will be able to add or deauthorize other admins, registrars, and voters.
Registrars will be able to add or deauthorize voters.
Both admins and registrars will be able to "audit" users' access permissions.

### Jurisdiction Users Page (Neither Admin nor Registrar)
Jurisdiction admins and registrars will also be listed and their certificate chains auditable.
Like anyone, they can see the voters' keys and count them from the jurisdiction's audit, but not who the voters are.

## Sub-jurisdictions Page
This page will have a separate list of all of the sub-jurisdictions under a jurisdiction.
Each jurisdiction will have a link to its own page.

### Authenticated Sub-jurisdiction Page (Admin)
For Admins, this page will have actions to create sub-jurisdictions.

## Jurisdiction Elections Page
This page will list all of the elections for the jurisdiction.
Default sorting will be most recent first.
Each election row/card will have a link to a separate page for that election.

### Authenticated Jurisdiction Elections Page (Admin)
This is where jurisdiction (or global) admins can create elections for a jurisdiction.

## Election Page
The Election Page will contain all information for a specific election, including title, a description, candidates/options, open and close date, whether or not the election was canceled, whether or not the election is hosted on a different instance, and potential links to external ballot boxes.

Candidates/options will include their associated image, name, and their description.
Candidates that have been removed will be visible separately.

Until the election closes, only the number of votes cast is shown, and with external ballot boxes, not even that. The tally is shown once it closes, so a change in the tally can't be matched to one voter's blind-signature request.
A downloadable file will be available once the election has concluded showing all cast votes with their nonces and signatures.
This downloadable file will likely be rather large (about 400 bytes per vote before encoding: a 32-byte nonce, a 120-byte vote and a 256-byte signature, so about 400MB per 1,000,000 votes), so we'll probably need to come up with a different system for distributing this (maybe quickly distribute to CDN or use something like WebTorrent?).

Once an admin publishes the results, a hash tree of the votes lets voters verify their vote without downloading the whole file.
However, showing something like that to a user may require some sort of explainer to allow them to trust the verification.
The root of the tree, along with the tally and the admin's signature publishing them, will be available for all clients to see.

The Election page has an Audit section for anyone, which checks the request that created the election and shows the fingerprints of the admin's key and the root's. Once the election closes, a button audits every published vote and blind-signature request, which downloads all of them (see What Browsers Check, under Auditing the System in the [main design document](../design.md)).
Later, the audit will also cover changes to the election and its candidates since it was created.

### Authenticated Election Page (Admin)
Admins will be able to update information for the election and candidates, and set up or cancel the election's external ballot boxes.
Once the election closes, admins over its jurisdiction can publish the results. Their browser checks the election's key against the request that created the election, checks every published vote and rebuilds the hash tree, then they sign its root and the tally. The server builds its own tree when they publish, and only accepts results that match it.

### Authenticated Election Page (Authorized Voter)
Authorized voters will be able to cast their vote, as well as check that their vote has been saved. Before using the election's key for either, their browser checks it against the request that created the election, and stops if it doesn't check out.

Once the election has closed, voters can check that their vote is among the published votes, which downloads every vote. Once the results are published, they check a proof from the hash tree that their vote is counted in the tally instead. If the server doesn't send the proof, they're warned, and can download every vote to check theirs instead. The proof is for their vote alone, so the server learns which vote they're checking. A later iteration of the design could have a proof cover a group of votes whose nonces start the same way (see Hashes in the [main design document](../design.md)).

The API calls pertaining to the unblinded vote will not be authenticated as the user to preserve some level of privacy of the vote.

## Account Page (Authentication required)
The Account page will have information for the user's account, and users will be able to change their password and other information. Eventually, we'll probably also want to include 2FA options.
It also shows the fingerprint of the anchor the account has pinned, and lets the user pin a different one after comparing its fingerprint.

## Global Admin Page (Global Admin permission required)
The global admin page will have a list of global admins and the ability for admins to add and remove other admins, as well as a link to the global settings page. It will also be where global admins create external elections from a host election's URL (see Election in the [main design document](../design.md)).

## Global Settings Page (Global Admin permission required)
The Global Settings page will have a list of all of the settings that can be changed on the fly by Global Admins. This could include requiring 2FA and setting other limits.
