package de.terrestris.keycloak.ldap

import org.jboss.logging.Logger
import org.keycloak.component.ComponentModel
import org.keycloak.models.GroupModel
import org.keycloak.models.RealmModel
import org.keycloak.models.RoleModel
import org.keycloak.models.UserModel
import org.keycloak.storage.ldap.LDAPStorageProvider
import org.keycloak.storage.ldap.idm.model.LDAPObject
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper
import java.util.stream.Collectors

inline fun <reified T> logger(): Logger {
  return Logger.getLogger(T::class.java)
}

class LdapDnMapper(mapperModel: ComponentModel, ldapProvider: LDAPStorageProvider?) :
  AbstractLDAPStorageMapper(mapperModel, ldapProvider) {

  companion object {
    val log = logger<LdapDnMapper>()
  }

  private val index: Int = mapperModel.config["index"]!![0].toString().toInt()
  private val createGroups: Boolean = java.lang.Boolean.parseBoolean(mapperModel.config["createGroups"]!![0])

  override fun onImportUserFromLDAP(ldapUser: LDAPObject, user: UserModel, realm: RealmModel, isCreate: Boolean) {
    var dn = ldapUser.dn
    val dnPath: MutableMap<String, MutableList<String>> = HashMap()
    do {
      val rdn = dn.firstRdn
      if (rdn.allKeys.isEmpty()) {
        continue
      }
      // dns may apparently contain multiple values per step like uid=john+sn=Doe, but we're ignoring this for now
      val key = rdn.allKeys[0]
      dnPath.computeIfAbsent(key) { k: String? -> ArrayList() }
      dnPath[key]!!.add(rdn.getAttrValue(key))
    } while (dn.parentDn.also { dn = it } != null && !dn.toString().isEmpty())
    val part = dnPath["ou"]!![index]
    if (createGroups) {
      val groups = realm.groupsStream.filter { g: GroupModel -> g.name == part }.collect(Collectors.toList())
      val group: GroupModel = if (groups.isEmpty()) {
        realm.createGroup(part)
      } else {
        groups[0]
      }
      if (!user.isMemberOf(group)) {
        user.joinGroup(group)
      }
    }
    var role = realm.getRole(part)
    if (role == null) {
      role = realm.addRole(part)
    }
    dnPath.forEach { (name: String?, values: List<String>?) -> user.setAttribute(name, values) }
    if (!user.hasRole(role)) {
      user.grantRole(role)
    }
  }

  override fun onRegisterUserToLDAP(ldapUser: LDAPObject, localUser: UserModel, realm: RealmModel) {
    // not supported
  }

  override fun proxy(ldapUser: LDAPObject, delegate: UserModel, realm: RealmModel): UserModel {
    onImportUserFromLDAP(ldapUser, delegate, realm, false)
    return delegate
  }

  override fun beforeLDAPQuery(query: LDAPQuery) {
    // not needed
  }

  override fun getRoleMembers(
    realm: RealmModel,
    role: RoleModel,
    firstResult: Int,
    maxResults: Int
  ): List<UserModel> {
    return super.getRoleMembers(realm, role, firstResult, maxResults)
  }

  init {
    log.debug("Using index $index")
    log.debug("Creating groups: " + if (createGroups) "yes" else "no")
  }

}
