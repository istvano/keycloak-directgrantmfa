package uk.co.urbanandco.keycloak.authentication.authenticators.conditional;

import com.google.auto.service.AutoService;
import java.util.Collections;
import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

@AutoService(AuthenticatorFactory.class)
public class ConditionalAuthNoteAuthenticatorFactory implements ConditionalAuthenticatorFactory {

  public static final String PROVIDER_ID = "conditional-auth-note";
  protected static final String CONDITIONAL_AUTH_NOTE = "auth-note";

  private static final List<ProviderConfigProperty> CONFIG_META_DATA;

  static {
    CONFIG_META_DATA = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
        .property().name(CONDITIONAL_AUTH_NOTE).label("Auth Note").helpText("Auth Note the user should not have to execute this flow").type(ProviderConfigProperty.STRING_TYPE).add()
        .build()
    );
  }

  @Override
  public String getDisplayType() {
    return "Condition - auth session note";
  }

  @Override
  public String getReferenceCategory() {
    return "condition";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  private static final Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Flow is executed only if user does NOT have the given session auth note.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_META_DATA;
  }

  @Override
  public ConditionalAuthenticator getSingleton() {
    return ConditionalAuthNoteAuthenticator.SINGLETON;
  }

  @Override
  public void init(Scope config) {

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}