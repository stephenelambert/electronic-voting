# User Stories
These are what each kind of user should be able to do in this system.

## Unauthenticated User ("As an unauthenticated user, I want to..."):
- register for an account.
- browse jurisdictions.
- browse elections and their candidates.
- view election results once an election closes.
- verify that votes have been properly counted.
- audit trust chains within the system (election/candidate setups, jurisdictions, etc.).
- pin the instance's anchor in my browser after comparing its fingerprint with one published outside the instance, so audits check every chain against it.

## Authorized Voter ("As an authorized voter, I want to..."):
- do everything an unauthenticated user can.
- log in with my username and password.
- have my account keep the anchor I pinned, so every device I log in on checks against it.
- browse elections for jurisdictions I'm part of (upcoming, active, and past).
- vote in elections for jurisdictions I'm part of.
- verify my vote in elections for jurisdictions I'm part of.
- finish casting my vote from another device if something goes wrong partway through.

## Jurisdiction Administrator ("As a jurisdiction administrator, I want to..."):
- create elections within my jurisdiction.
- update elections within my jurisdiction.
- cancel elections within my jurisdiction.
- publish the results of elections within my jurisdiction.
- create candidates for elections within my jurisdiction.
- update candidates for elections within my jurisdiction.
- take candidates off the ballot for elections within my jurisdiction.
- create sub-jurisdictions under my jurisdiction.
- update sub-jurisdictions under mine.
- deactivate sub-jurisdictions under mine.
- update my jurisdiction.
- deactivate my jurisdiction.
- add admins for my jurisdiction.
- remove admins for my jurisdiction.
- add admins for sub-jurisdictions under mine.
- remove admins for sub-jurisdictions under mine.
- do everything registrars for my jurisdiction can do.
- authorize jurisdiction registrars for my jurisdiction.
- deauthorize jurisdiction registrars for my jurisdiction.
- authorize registrars for sub-jurisdictions under mine.
- deauthorize registrars for sub-jurisdictions under mine.
- create external ballot boxes for elections within my jurisdiction.
- cancel external ballot boxes for elections within my jurisdiction.

## Jurisdiction Registrar ("As a Jurisdiction Registrar, I want to..."):
- authorize voters for my jurisdiction.
- deauthorize voters for my jurisdiction.
- authorize voters for sub-jurisdictions under mine.
- deauthorize voters for sub-jurisdictions under mine.

## Global Administrators ("As a Global Administrator, I want to..."):
- do everything jurisdiction administrators can do, for all jurisdictions.
- create jurisdictions.
- create external elections, to receive votes for elections hosted on other instances.
- add global administrators.
- remove global administrators.
- update system-wide settings.
