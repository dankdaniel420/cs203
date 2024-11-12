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
		User user110 = new User("User110", encoder.encode("user1234"), "ROLE_USER", 110);
		User user150 = new User("User150", encoder.encode("user1234"), "ROLE_USER", 150);
		User user100 = new User("User100", encoder.encode("user1234"), "ROLE_USER", 100);
		System.out.println("[Add Admin]: " + users.save(new User("Admin", encoder.encode("password123"), "ROLE_ADMIN", 0)).getUsername());
		System.out.println("[Add User]: " + users.save(new User("User0", encoder.encode("user1234"), "ROLE_USER", 0)).getUsername());
		System.out.println("[Add User]: " + users.save(user110).getUsername());
		System.out.println("[Add User]: " + users.save(user150).getUsername());
		System.out.println("[Add User]: " + users.save(user100).getUsername());
		System.out.println("[Add User]: " + users.save(new User("User120", encoder.encode("user1234"), "ROLE_USER", 120)).getUsername());
		System.out.println("[Add Bot]: " + users.save(new User("DEFAULT_BOT", encoder.encode("goodpassword"), "ROLE_USER", -1)).getUsername());

		// JPA User Repository init
		TournamentService Ts = ctx.getBean(TournamentService.class);
		Tournament t = new Tournament();
		t.setTitle("Tournament A");
		t.setSize(4);
		t.setTotalRounds(2);
		t.setMaxElo(200);
		t.setStartDateTime(LocalDateTime.of(2024, 9, 30, 15, 45));
		System.out.println("[Add Tournament]: " + Ts.addTournament(t).getTitle());
		Tournament t1 = new Tournament();
		t1.setTitle("Tournament B");
		t1.setSize(5);
		t1.setMaxElo(200);
		t1.setTotalRounds(1);
		t1.setStartDateTime(LocalDateTime.of(2024, 12, 20, 15, 0));
		System.out.println("[Add Tournament]: " + Ts.addTournament(t1).getTitle());
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
