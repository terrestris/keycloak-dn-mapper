package de.terrestris.keycloak.ldap

import org.keycloak.component.ComponentModel
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.storage.ldap.LDAPStorageProvider
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory

class LdapMapperFactory : AbstractLDAPStorageMapperFactory() {
  companion object {
    private val configProperties: MutableList<ProviderConfigProperty> = ArrayList()

    init {
      val indexAttr = createConfigProperty(
        "index", "Index",
        "The index number pointing to the part of the dn's ou parts to use for the role",
        ProviderConfigProperty.STRING_TYPE, null
      )
      val createGroupAttr = createConfigProperty(
        "createGroups", "Create groups",
        "If checked, a group will be created along with the role",
        ProviderConfigProperty.BOOLEAN_TYPE, null
      )
      configProperties.add(indexAttr)
      configProperties.add(createGroupAttr)
    }
  }

  override fun getConfigProperties(): List<ProviderConfigProperty> {
    return Companion.configProperties
  }

  override fun getId(): String {
    return "ldap-dn-mapper"
  }

  override fun createMapper(
    mapperModel: ComponentModel,
    federationProvider: LDAPStorageProvider
  ): AbstractLDAPStorageMapper {
    return LdapDnMapper(mapperModel, federationProvider)
  }

  override fun getHelpText(): String {
    return "Map a part of the dn to a role and assign the user to it"
  }

  override fun getTypeMetadata(): Map<String, Any> {
    val metadata: MutableMap<String, Any> = HashMap()
    metadata["fedToKeycloakSyncSupported"] = true
    metadata["keycloakToFedSyncSupported"] = false
    return metadata
  }

}