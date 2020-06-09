package uk.co.urbanandco.keycloak.authentication.actiontoken;

import com.google.auto.service.AutoService;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config.Scope;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHander;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import uk.co.urbanandco.keycloak.representations.MfaActionRepresentation;

@JBossLog
@AutoService(ActionTokenHandlerFactory.class)
public class MfaManagerSendOtpActionTokenHandler extends
    AbstractActionTokenHander<MfaManagerSendOtpActionToken> {

  private String apiUrl;

  public MfaManagerSendOtpActionTokenHandler() {
    super(
        MfaManagerSendOtpActionToken.TOKEN_TYPE,
        MfaManagerSendOtpActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST
    );
  }

  @Override
  public void init(Scope config) {
    // this configuration is pulled from the SPI configuration of this provider in the standalone[-ha] / domain.xml
    // see develop.cli
    apiUrl = config.get("connectionUrl");
    log.infov("Configured {0} with connectionUrl: {1}", this, apiUrl);
  }

  @Override
  public Response handleToken(MfaManagerSendOtpActionToken token,
      ActionTokenContext<MfaManagerSendOtpActionToken> tokenContext) {

    //TODO send the request to the mfa service to send a one time password to the user
    MfaActionRepresentation rep = new MfaActionRepresentation(generateVerificationToken(tokenContext, token.getUserId(), token.getApplicationId()));
    return Response.ok(rep, MediaType.APPLICATION_JSON_TYPE).build();
  }

  @Override
  public Predicate<? super MfaManagerSendOtpActionToken>[] getVerifiers(
      ActionTokenContext<MfaManagerSendOtpActionToken> tokenContext) {
    return new Predicate[0];
  }

  public String generateVerificationToken(ActionTokenContext<MfaManagerSendOtpActionToken> context, String userId, String applicationId) {

    int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
    int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
    final AuthenticationSessionModel authSession = context.getAuthenticationSession();
    final String clientId = authSession.getClient().getClientId();

    return new MfaManagerVerifyOtpActionToken(
        userId,
        absoluteExpirationInSecs,
        clientId,
        applicationId
    ).serialize(
        context.getSession(),
        context.getRealm(),
        context.getUriInfo()
    );

  }

}
