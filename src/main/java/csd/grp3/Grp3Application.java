package csd.grp3;

import java.time.LocalDateTime;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import csd.grp3.user.UserRepository;
import csd.grp3.tournament.Tournament;
import csd.grp3.tournament.TournamentRepository;
import csd.grp3.tournament.TournamentService;
import csd.grp3.round.RoundRepository;
import csd.grp3.match.MatchRepository;
import csd.grp3.user.User;

@SpringBootApplication
public class Grp3Application {

	public static void main(String[] args) {
		ApplicationContext ctx = SpringApplication.run(Grp3Application.class, args);
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		// JPA User Repository init
		UserRepository users = ctx.getBean(UserRepository.class);
		User admin = new User();
		admin.setUsername("Admin");
		admin.setPassword(encoder.encode("pass1234"));
		admin.setAuthorities("ROLE_ADMIN");
		System.out.println("[Add Admin]: " + users.save(admin).getUsername());
		User user = new User( "User", encoder.encode("user1234"));
		System.out.println("[Add User]: " + users.save(user).getUsername()); // , "ROLE_USER", 100


		// JPA User Repository init
		TournamentRepository ts = ctx.getBean(TournamentRepository.class);
		Tournament t = new Tournament();
		t.setTitle("Tournament A");
		t.setSize(2);
		t.setDate(LocalDateTime.of(2024, 9, 30, 15, 45));
		System.out.println("[Add Tournament]: " + ts.save(t).getTitle());
		Tournament t1 = new Tournament();
		t1.setTitle("Tournament B");
		t1.setDate(LocalDateTime.of(2024, 10, 20, 15, 0));
		t1.setSize(4);
		System.out.println("[Add Tournament]: " + ts.save(t1).getTitle());
		
		TournamentService Ts = ctx.getBean(TournamentService.class);
		RoundRepository rs = ctx.getBean(RoundRepository.class);
		MatchRepository ms = ctx.getBean(MatchRepository.class);
		Ts.registerPlayer(admin, 1L);
		Ts.registerPlayer(user, 1L);
		Ts.addRound(1L);
		System.out.println("[Add Round]: added to Tournament Id 1");
		System.out.println(t.getRounds());
	}

}
