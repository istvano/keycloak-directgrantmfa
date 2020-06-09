package uk.co.urbanandco.keycloak.authentication.authenticators.directgrant;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

import com.google.auto.service.AutoService;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

@JBossLog
@AutoService(AuthenticatorFactory.class)
public class MfaManagerValidateOtpAuthenticatorFactory implements AuthenticatorFactory {

  public static final String ID = "mfa-man-direct-otp-authenticator";
  public static final String CONFIG_APPLICATION_ID = "mfa-id";
  private static final List<ProviderConfigProperty> CONFIG_META_DATA;

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED
  };

  static {
    CONFIG_META_DATA = ProviderConfigurationBuilder.create()
        .property()
        .name(CONFIG_APPLICATION_ID)
        .type(STRING_TYPE)
        .label("Mfa ID")
        .defaultValue(MfaManagerValidateOtpAuthenticator.DEFAULT_MFA_ID)
        .helpText("External MFA ID sent in the token")
        .add()
        .build();
  }

  @Override
  public String getDisplayType() {
    return "External MFA Authenticator";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "External MFA Authenticator";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return CONFIG_META_DATA;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new MfaManagerValidateOtpAuthenticator();
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
    return ID;
  }
}
