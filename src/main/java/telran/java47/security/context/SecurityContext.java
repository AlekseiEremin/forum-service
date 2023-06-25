package telran.java47.security.context;

import telran.java47.security.model.User;

public interface SecurityContext {
	
	User addUserSession(String sessionId, User user);

	User removeUser(String sessionId);

	User getUserBySessionId(String sessionId);
}
