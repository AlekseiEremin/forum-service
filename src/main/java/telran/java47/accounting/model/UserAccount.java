package telran.java47.accounting.model;

import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import telran.java47.security.model.Roles;

@Getter
@Document(collection = "users")
public class UserAccount {
	@Id
	String login;
	@Setter
	String password;
	@Setter
	String firstName;
	@Setter
	String lastName;
	Set<Roles> roles;
	
	public UserAccount() {
		roles = new HashSet<>();
	}

	public UserAccount(String login, String password, String firstName, String lastName) {
		this();
		this.login = login;
		this.password = password;
		this.firstName = firstName;
		this.lastName = lastName;
	}

	public boolean addRole(Roles role) {
		return roles.add(role);
	}

	public boolean removeRole(Roles role) {
		return roles.remove(role);
	}

}
