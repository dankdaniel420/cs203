package csd.grp3.tournament;

import csd.grp3.user.User;
import csd.grp3.round.Round;

import java.util.List;

import org.springframework.stereotype.Service;

@Service
public interface TournamentService {
    List<Tournament> listTournaments();
    Tournament getTournament(Long id);
    Tournament addTournament(Tournament tournament);
    Tournament updateTournament(Long id, Tournament tournament);
    void deleteTournament(Long id);
    void registerUser(User user, Long id);
    void withdrawUser(User user, Long id);
    void updateResults(Round round);
    String directEncounterResultInTournament(Tournament tournament, User user1, User user2);
    void endTournament(Long id);
    List<Tournament> getTournamentAboveMin(int ELO);
    List<Tournament> getTournamentBelowMax(int ELO);
}
