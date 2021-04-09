# Keycloak LDAP dn mapper

## Install

If using the official keycloak docker image you can create a mount of the directory 
`/opt/jboss/keycloak/standalone/deployments` and copy the jar there.

## Usage

When using the mapper, you can configure

* the index of the ou to use as a group/role name
* whether to create a group or not

The mapper will then extract the parts of the user's dn and (for a dn like 
`cn=hwbllmnn,ou=user,ou=developer,ou=homeoffice,o=terrestris`):

* add the parts of the dn to the keycloak user's attributes sorted by key, like so:

```
cn: ["hwbllmnn"],
o: ["terrestris"],
ou: ["user", developer", "homeoffice"]
```

* create a role based on the index into the ou list configured
* if switched on, create a group with the same name
* grant the role to the user
* add the user to the group if configured
