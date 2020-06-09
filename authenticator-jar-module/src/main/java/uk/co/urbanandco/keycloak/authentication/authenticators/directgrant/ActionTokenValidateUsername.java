package uk.co.urbanandco.keycloak.authentication.authenticators.directgrant;

import com.google.auto.service.AutoService;
import javax.ws.rs.core.MultivaluedMap;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.authentication.authenticators.directgrant.ValidateUsername;
import org.keycloak.services.managers.AuthenticationManager;

@JBossLog
@AutoService(AuthenticatorFactory.class)
public class ActionTokenValidateUsername extends ValidateUsername {
  public static final String PROVIDER_ID = "action-token-direct-username";

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Mfa Man Username Validation";
  }

  @Override
  protected String retrieveUsername(AuthenticationFlowContext context) {
    String userId = context.getAuthenticationSession().getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
    if (userId != null && !userId.isEmpty()) {
      return userId;
    } else {
      MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
      return inputData.getFirst(AuthenticationManager.FORM_USERNAME);
    }
  }

}
