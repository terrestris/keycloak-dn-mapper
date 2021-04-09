package de.terrestris.keycloak.ldap;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPDn;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@JBossLog
public class LdapDnMapper extends AbstractLDAPStorageMapper {

  private final int index;

  private final boolean createGroups;

  public LdapDnMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
    super(mapperModel, ldapProvider);
    index = Integer.parseInt(String.valueOf(mapperModel.getConfig().get("index").get(0)));
    createGroups = Boolean.parseBoolean(mapperModel.getConfig().get("createGroups").get(0));
    log.debug("Using index " + index);
    log.debug("Creating groups: " + (createGroups ? "yes" : "no"));
  }

  @Override
  public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
    LDAPDn dn = ldapUser.getDn();
    Map<String, List<String>> dnPath = new HashMap<>();
    do {
      LDAPDn.RDN rdn = dn.getFirstRdn();
      if (rdn.getAllKeys().isEmpty()) {
        continue;
      }
      // dns may apparently contain multiple values per step like uid=john+sn=Doe, but we're ignoring this for now
      String key = rdn.getAllKeys().get(0);
      dnPath.computeIfAbsent(key, k -> new ArrayList<>());
      dnPath.get(key).add(rdn.getAttrValue(key));
    } while ((dn = dn.getParentDn()) != null && !dn.toString().isEmpty());

    String part = dnPath.get("ou").get(index);
    if (createGroups) {
      List<GroupModel> groups = realm.getGroupsStream().filter(g -> g.getName().equals(part)).collect(Collectors.toList());
      GroupModel group;
      if (groups.isEmpty()) {
        group = realm.createGroup(part);
      } else {
        group = groups.get(0);
      }
      user.joinGroup(group);
    }
    RoleModel role = realm.getRole(part);
    if (role == null) {
      role = realm.addRole(part);
    }

    dnPath.forEach(user::setAttribute);
    user.grantRole(role);
  }

  @Override
  public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
    // not supported
  }

  @Override
  public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
    onImportUserFromLDAP(ldapUser, delegate, realm, false);
    return delegate;
  }

  @Override
  public void beforeLDAPQuery(LDAPQuery query) {
    // not needed
  }

  @Override
  public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role, int firstResult, int maxResults) {
    return super.getRoleMembers(realm, role, firstResult, maxResults);
  }

}
