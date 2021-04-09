package de.terrestris.keycloak.ldap;

import org.keycloak.component.ComponentModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LdapMapperFactory extends AbstractLDAPStorageMapperFactory {

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  static {
    ProviderConfigProperty indexAttr = createConfigProperty("index", "Index",
      "The index number pointing to the part of the dn's ou parts to use for the role",
      ProviderConfigProperty.STRING_TYPE, null);
    ProviderConfigProperty createGroupAttr = createConfigProperty("createGroups", "Create groups",
      "If checked, a group will be created along with the role",
      ProviderConfigProperty.BOOLEAN_TYPE, null);
    configProperties.add(indexAttr);
    configProperties.add(createGroupAttr);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public String getId() {
    return "ldap-dn-mapper";
  }

  @Override
  protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
    return new LdapDnMapper(mapperModel, federationProvider);
  }

  @Override
  public String getHelpText() {
    return "Map a part of the dn to a role and assign the user to it";
  }

  @Override
  public Map<String, Object> getTypeMetadata() {
    Map<String, Object> metadata = new HashMap<>();
    metadata.put("fedToKeycloakSyncSupported", true);
    metadata.put("keycloakToFedSyncSupported", false);
    return metadata;
  }

}
