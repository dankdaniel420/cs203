package csd.grp3;

import java.time.LocalDateTime;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.client.RestTemplate;

import csd.grp3.user.UserRepository;
import csd.grp3.tournament.Tournament;
import csd.grp3.tournament.TournamentService;
import csd.grp3.user.User;

@SpringBootApplication
public class Grp3Application {

	public static void main(String[] args) {
		ApplicationContext ctx = SpringApplication.run(Grp3Application.class, args);
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

		// JPA User Repository init
		UserRepository users = ctx.getBean(UserRepository.class);
		User user100 = new User("User100", encoder.encode("user1234"), "ROLE_USER", 100);
		User user120 = new User("User120", encoder.encode("user1234"), "ROLE_USER", 120);
		User user130 = new User("User130", encoder.encode("user1234"), "ROLE_USER", 130);
		User user140 = new User("User140", encoder.encode("user1234"), "ROLE_USER", 140);
		User user150 = new User("User150", encoder.encode("user1234"), "ROLE_USER", 150);
		User user170 = new User("User170", encoder.encode("user1234"), "ROLE_USER", 170);
		User user190 = new User("User190", encoder.encode("user1234"), "ROLE_USER", 190);
		User user200 = new User("User200", encoder.encode("user1234"), "ROLE_USER", 200);
		User user220 = new User("User220", encoder.encode("user1234"), "ROLE_USER", 220);
		User user240 = new User("User240", encoder.encode("user1234"), "ROLE_USER", 240);
		User user260 = new User("User260", encoder.encode("user1234"), "ROLE_USER", 260);
		User user280 = new User("User280", encoder.encode("user1234"), "ROLE_USER", 280);
		System.out.println("[Add Admin]: " + users.save(new User("Admin", encoder.encode("password123"), "ROLE_ADMIN", 0)).getUsername());
		System.out.println("[Add User]: " + users.save(new User("User0", encoder.encode("user1234"), "ROLE_USER", 0)).getUsername());
		// user100.setSuspicious(true);
		System.out.println("[Add User]: " + users.save(user100).getUsername());
		System.out.println("[Add User]: " + users.save(user120).getUsername());
		System.out.println("[Add User]: " + users.save(user130).getUsername());
		System.out.println("[Add User]: " + users.save(user140).getUsername());
		System.out.println("[Add User]: " + users.save(user150).getUsername());
		System.out.println("[Add User]: " + users.save(user200).getUsername());
		System.out.println("[Add User]: " + users.save(user220).getUsername());
		System.out.println("[Add User]: " + users.save(user240).getUsername());
		System.out.println("[Add User]: " + users.save(user260).getUsername());
		System.out.println("[Add User]: " + users.save(user280).getUsername());
		System.out.println("[Add User]: " + users.save(user170).getUsername());
		System.out.println("[Add User]: " + users.save(user190).getUsername());
		System.out.println("[Add Bot]: " + users.save(new User("DEFAULT_BOT", encoder.encode("goodpassword"), "ROLE_USER", -1)).getUsername());

		// JPA User Repository init
		TournamentService Ts = ctx.getBean(TournamentService.class);
		Tournament t = new Tournament();
		t.setTitle("Tournament A");
		t.setSize(12);
		t.setTotalRounds(5);
		t.setMaxElo(300);
		t.setStartDateTime(LocalDateTime.of(2024, 9, 30, 15, 45));
		System.out.println("[Add Tournament]: " + Ts.addTournament(t).getTitle());
		Ts.registerUser(user100, t.getId());
		Ts.registerUser(user120, t.getId());
		Ts.registerUser(user130, t.getId());
		Ts.registerUser(user140, t.getId());
		Ts.registerUser(user150, t.getId());
		Ts.registerUser(user200, t.getId());
		Ts.registerUser(user220, t.getId());
		Ts.registerUser(user240, t.getId());
		Ts.registerUser(user260, t.getId());
		Ts.registerUser(user280, t.getId());
		Ts.registerUser(user170, t.getId());
		Ts.registerUser(user190, t.getId());
		
		Tournament t1 = new Tournament();
		t1.setTitle("Tournament B");
		t1.setSize(5);
		t1.setMaxElo(200);
		t1.setTotalRounds(5);
		t1.setStartDateTime(LocalDateTime.of(2024, 9, 20, 15, 0));
		System.out.println("[Add Tournament]: " + Ts.addTournament(t1).getTitle());
		Ts.registerUser(user100, t1.getId());
		Ts.registerUser(user120, t1.getId());
		Ts.registerUser(user130, t1.getId());
		Ts.registerUser(user140, t1.getId());
		Tournament t2 = new Tournament();
		t2.setTitle("Tournament C");
		t2.setSize(3);
		t2.setMaxElo(200);
		t2.setTotalRounds(3);
		t2.setStartDateTime(LocalDateTime.of(2024, 12, 31, 15, 0));
		Ts.addTournament(t2);
	}

	@Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}