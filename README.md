# IAM explored through Code Labs

What you'll discover in this set of labs is how they frame the technologies behind many IAM products, my focus has been on the Forgerock stack so this describes their stack and the labs you'll see

## ForgeRock AM: IdP / Access Mgmt (OIDC/OAuth2, SAML, sessions, “journeys”/trees, policy, token minting/extensibility)

Saml is explored in the /src/saml codebase and documentation - exploring how SAML is used in SSO, how users are validated and the flow of information when logging in.

*Coming Soon* Explorartion on the OIDC and OAuth2 protocols in Nodejs.

## ForgeRock DS: LDAP directory used as identity store and/or config store (depending on deployment)

LDAP is explored in the /src/ds codebase and documentation - exploring how to setup a basic LDAP server, viewingits capabilities, binding (logging in) and searching the database for people and groups.


## ForgeRock IDM: lifecycle + provisioning + reconciliation (the JML “joiner/mover/leaver” shape)

Basic lifecycle activities are explored in the /src/ds codebase and documentation simply adding and removing users.  Custom JML activities could be modelled in code but IDM's power comes from its workflows, custom approaches could be reading the LDAP servers tail logs and generating a custom codebase to do something on recognised events like user deleted.


## ForgeRock IG: policy enforcement / gateway / reverse proxy patterns (authenticate via AM, token exchange, route to upstreams)

We emulated token exchange in the /src/saml codebase

*Coming Soon* an exploration of IG facilities and how it achieves adapting services and websites to be integrated with AM

