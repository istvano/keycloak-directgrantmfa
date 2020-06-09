package uk.co.urbanandco.keycloak.authentication.actiontoken;

import static uk.co.urbanandco.keycloak.authentication.actiontoken.MfaManagerVerifyOtpActionToken.INITIATED_BY_ACTION_TOKEN_EXT_APP;

import com.google.auto.service.AutoService;
import java.util.Map;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHander;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.Cors;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.StorageId;
import org.keycloak.util.TokenUtil;

@JBossLog
@AutoService(ActionTokenHandlerFactory.class)
public class MfaManagerVerifyOtpActionTokenHandler extends
    AbstractActionTokenHander<MfaManagerVerifyOtpActionToken> {

  private TokenManager tokenManager = new TokenManager();

  public MfaManagerVerifyOtpActionTokenHandler() {
    super(
        MfaManagerVerifyOtpActionToken.TOKEN_TYPE,
        MfaManagerVerifyOtpActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST
    );
    tokenManager = new TokenManager();
  }

  @Override
  public Response handleToken(MfaManagerVerifyOtpActionToken token,
      ActionTokenContext<MfaManagerVerifyOtpActionToken> tokenContext) {

    KeycloakSession session = tokenContext.getSession();
    RealmModel realm = tokenContext.getRealm();
    EventBuilder event = tokenContext.getEvent();
    AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    ClientModel client = authSession.getClient();
    Cors cors = Cors.add(tokenContext.getRequest()).auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

    String scope = getRequestedScopes(event, cors, client, tokenContext);

    authSession.setAuthNote(INITIATED_BY_ACTION_TOKEN_EXT_APP, "true");
    StorageId id = new StorageId(token.getUserId());
    UserModel userById = getUser(tokenContext, id);

    authSession.setAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID, userById.getUsername());
    authSession.setAuthNote(OTPCredentialModel.TYPE, getRequestedOtp(tokenContext));

    authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
    authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());
    authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls
        .realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
    authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

    AuthenticationFlowModel flow = AuthenticationFlowResolver.resolveDirectGrantFlow(authSession);
    String flowId = flow.getId();
    AuthenticationProcessor processor = new AuthenticationProcessor();
    processor.setAuthenticationSession(authSession)
        .setFlowId(flowId)
        .setConnection(tokenContext.getClientConnection())
        .setEventBuilder(tokenContext.getEvent())
        .setRealm(realm)
        .setSession(session)
        .setUriInfo(session.getContext().getUri())
        .setRequest(tokenContext.getRequest());

    Response challenge = processor.authenticateOnly();
    if (challenge != null) {
      //cors.build(response);
      return challenge;
    }

    processor.evaluateRequiredActionTriggers();
    UserModel user = authSession.getAuthenticatedUser();
    if (user.getRequiredActions() != null && !user.getRequiredActions().isEmpty()) {
      event.error(Errors.RESOLVE_REQUIRED_ACTIONS);
      throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "Account is not fully set up", Status.BAD_REQUEST);

    }

    AuthenticationManager.setClientScopesInSession(authSession);

    ClientSessionContext clientSessionCtx = processor.attachSession();
    UserSessionModel userSession = processor.getUserSession();
    updateUserSessionFromClientAuth(userSession, authSession);

    TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager.responseBuilder(realm, client, event, session, userSession, clientSessionCtx)
        .generateAccessToken()
        .generateRefreshToken();

    String scopeParam = clientSessionCtx.getClientSession().getNote(OAuth2Constants.SCOPE);
    if (TokenUtil.isOIDCRequest(scopeParam)) {
      responseBuilder.generateIDToken();
    }

    // TODO : do the same as codeToToken()
    AccessTokenResponse res = responseBuilder.build();

    event.success();

    return Response.ok(res, MediaType.APPLICATION_JSON_TYPE).build();
  }

  private static String getRequestedOtp(ActionTokenContext<MfaManagerVerifyOtpActionToken> tokenContext) {
    MultivaluedMap<String, String> queryParams = tokenContext.getUriInfo().getQueryParameters();
    return queryParams.getFirst(OTPCredentialModel.TYPE);
  }

  private static String getRequestedScopes(EventBuilder event, Cors cors, ClientModel client,
      ActionTokenContext<MfaManagerVerifyOtpActionToken> tokenContext) {

    MultivaluedMap<String, String> formParams = tokenContext.getRequest().getDecodedFormParameters();
    if (formParams == null || formParams.isEmpty()) {
      formParams = tokenContext.getUriInfo().getQueryParameters();
    }

    String scope = formParams.getFirst(OAuth2Constants.SCOPE);

    if (!TokenManager.isValidScope(scope, client)) {
      event.error(Errors.INVALID_REQUEST);
      throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_SCOPE, "Invalid scopes: " + scope,
          Status.BAD_REQUEST);
    }

    return scope;
  }

  private static void updateUserSessionFromClientAuth(UserSessionModel userSession,
      AuthenticationSessionModel authSession) {
    if (authSession.getClientNotes() != null) {
      for (Map.Entry<String, String> attr : authSession.getClientNotes().entrySet()) {
        userSession.setNote(attr.getKey(), attr.getValue());
      }
    }
  }

  @Override
  public Predicate<? super MfaManagerVerifyOtpActionToken>[] getVerifiers(
      ActionTokenContext<MfaManagerVerifyOtpActionToken> tokenContext) {
    return new Predicate[0];
  }

  private static UserModel getUser(ActionTokenContext<MfaManagerVerifyOtpActionToken> context, StorageId storageId) {
    try {
      return context.getSession().userStorageManager().getUserById(storageId.getId(), context.getRealm());
    } catch (ModelDuplicateException e) {
      log.error("Duplicate user was found ", e);
      return null;
    }
  }

}
