package csd.grp3.usertournament;

import java.util.Iterator;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import csd.grp3.tournament.Tournament;
import csd.grp3.user.User;
import jakarta.transaction.Transactional;

@Service
public class UserTournamentServiceImpl implements UserTournamentService {

    @Autowired
    private UserTournamentRepository userTournamentRepo;

    @Override
    public UserTournament findRecord(Long tournamentID, String username) throws UserTournamentNotFoundException {
        return userTournamentRepo.findById_TournamentIdAndId_Username(tournamentID, username)
                .orElseThrow(() -> new UserTournamentNotFoundException());
    }

    @Override
    public List<User> getPlayers(Long tournamentID) {
        // Get the list of users
        List<User> users = userTournamentRepo.findRegisteredUsersByTournamentId(tournamentID);

        // Remove the users whose username is "DEFAULT_BOT"
        users.removeIf(user -> user.getUsername().equals("DEFAULT_BOT"));

        // Return the filtered list
        return users;
    }

    @Override
    public List<User> getWaitingList(Long tournamentID) {
        return userTournamentRepo.findWaitlistUsersByTournamentId(tournamentID);
    }

    @Override
    public double getGamePoints(Long tournamentID, String username) {
        UserTournament userTournament = findRecord(tournamentID, username);
        return userTournament.getGamePoints();
    }

    @Override
    public void updateGamePoints(Long tournamentID, String username) {
        UserTournament userTournament = findRecord(tournamentID, username);
        userTournament.setGamePoints(userTournament.getGamePoints()); // getGamePoints adds MatchPoints
        userTournament.setMatchPoints(0); // reset match points
        userTournamentRepo.save(userTournament);
    }

    @Override
    public void updateMatchPoints(Long tournamentID, String username, double points) {
        UserTournament userTournament = findRecord(tournamentID, username);
        userTournament.setMatchPoints(points);
        userTournamentRepo.save(userTournament);
    }

    @Override
    public UserTournament updatePlayerStatus(Long tournamentID, String username, char status) {
        UserTournament userTournament = findRecord(tournamentID, username);
        userTournament.setStatus(status);
        return userTournamentRepo.save(userTournament);
    }

    @Override
    @Transactional
    public UserTournament add(Tournament tournament, User user, char status) {
        // Check if the UserTournament already exists
        Optional<UserTournament> existinguserTournament = userTournamentRepo.findById_TournamentIdAndId_Username(
                tournament.getId(),
                user.getUsername());
        if (existinguserTournament.isPresent()) {
            return updatePlayerStatus(tournament.getId(), user.getUsername(), status);
        }

        UserTournament userTournament = new UserTournament(
                new UserTournamentId(tournament.getId(), user.getUsername()),
                tournament, user, status, 0, 0);

        // Add the userTournament to both parent entities' lists
        tournament.getUserTournaments().add(userTournament);
        user.getUserTournaments().add(userTournament);

        return userTournament;
    }

    @Override
    @Transactional
    public void delete(Tournament tournament, User user) {
        // Remove the userTournament from both parent entities' lists
        UserTournament userTournament = findRecord(tournament.getId(), user.getUsername());
        tournament.getUserTournaments().remove(userTournament);
        user.getUserTournaments().remove(userTournament);
        userTournamentRepo.deleteById_TournamentIdAndId_Username(tournament.getId(), user.getUsername());
    }
}