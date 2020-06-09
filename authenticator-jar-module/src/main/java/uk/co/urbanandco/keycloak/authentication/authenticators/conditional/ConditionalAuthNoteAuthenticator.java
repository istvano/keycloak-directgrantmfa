package uk.co.urbanandco.keycloak.authentication.authenticators.conditional;

import com.google.common.base.Strings;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class ConditionalAuthNoteAuthenticator implements ConditionalAuthenticator {
  public static final ConditionalAuthNoteAuthenticator SINGLETON = new ConditionalAuthNoteAuthenticator();

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
    //process by default and only ignore if the session has a note
    boolean result = true;
    if (user != null && authConfig!=null && authConfig.getConfig()!=null) {
      String authNote = authConfig.getConfig().get(ConditionalAuthNoteAuthenticatorFactory.CONDITIONAL_AUTH_NOTE);
      if (!Strings.isNullOrEmpty(authNote)) {
        String userAuthNote = context.getAuthenticationSession().getAuthNote(authNote);
        result = Strings.isNullOrEmpty(userAuthNote);
      }
    }
    return result;
  }

  @Override
  public void action(AuthenticationFlowContext authenticationFlowContext) {
    //intentionally left empty
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {

  }

  @Override
  public void close() {

  }
}
