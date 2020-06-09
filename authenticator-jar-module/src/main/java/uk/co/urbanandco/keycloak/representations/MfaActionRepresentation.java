package uk.co.urbanandco.keycloak.representations;

import com.fasterxml.jackson.annotation.JsonProperty;

public class MfaActionRepresentation {
  public static final String VERIFY_TOKEN = "verify_token";

  private String verifyToken;

  @JsonProperty(MfaActionRepresentation.VERIFY_TOKEN)
  public String getVerifyToken() {
    return verifyToken;
  }

  public void setVerifyToken(String verifyToken) {
    this.verifyToken = verifyToken;
  }

  public MfaActionRepresentation(String verifyToken) {
    this.verifyToken = verifyToken;
  }
}
