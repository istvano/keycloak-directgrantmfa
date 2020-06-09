package uk.co.urbanandco.keycloak.events;

import com.google.auto.service.AutoService;
import java.util.HashSet;
import java.util.Set;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

@AutoService(EventListenerProviderFactory.class)
public class CustomEventListenerProviderFactory  implements EventListenerProviderFactory {
  private Set<EventType> excludedEvents;
  private Set<OperationType> excludedAdminOperations;

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new CustomEventListenerProvider(excludedEvents, excludedAdminOperations);
  }

  @Override
  public void init(Config.Scope config) {
    String[] excludes = config.getArray("exclude-events");
    if (excludes != null) {
      excludedEvents = new HashSet<>();
      for (String e : excludes) {
        excludedEvents.add(EventType.valueOf(e));
      }
    }

    String[] excludesOperations = config.getArray("excludesOperations");
    if (excludesOperations != null) {
      excludedAdminOperations = new HashSet<>();
      for (String e : excludesOperations) {
        excludedAdminOperations.add(OperationType.valueOf(e));
      }
    }
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }
  @Override
  public void close() {
  }

  @Override
  public String getId() {
    return "custom-events";
  }
}
