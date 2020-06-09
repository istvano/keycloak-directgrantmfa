package uk.co.urbanandco.keycloak.representations.idm;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

public class OAuth2TokenErrorRepresentation extends OAuth2ErrorRepresentation {

  public static final String MFA_TOKEN = "mfa_token";

  private String mfaToken;

  public OAuth2TokenErrorRepresentation() {
    super();
  }

  public OAuth2TokenErrorRepresentation(String error, String errorDescription, String token) {
    super(error, errorDescription);
    mfaToken = token;
  }

  @JsonProperty(OAuth2TokenErrorRepresentation.MFA_TOKEN)
  public String getMfaToken() {
    return mfaToken;
  }

  public void setMfaToken(String mfaToken) {
    this.mfaToken = mfaToken;
  }

}
