package csd.grp3.tournament;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import csd.grp3.round.Round;
import csd.grp3.user.User;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping("/tournaments")
public class TournamentController {
    
    private TournamentService tournamentService;

    @GetMapping
    public ResponseEntity<List<Tournament>> getAllTournaments() {
        List<Tournament> tournamentList = tournamentService.listTournaments();
        return ResponseEntity.status(HttpStatus.OK).body(tournamentList);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Tournament> getTournamentById(@PathVariable Long id) {
        Tournament tournamentData = tournamentService.getTournament(id);
        return new ResponseEntity<>(tournamentData, HttpStatus.OK);
    }

    @GetMapping("/{id}/rounds")
    public ResponseEntity<List<Round>> getRoundData(@PathVariable Long id) {
        Tournament tournamentData = tournamentService.getTournament(id);
        if (!tournamentData.isOver()) {
            tournamentService.addRound(id);
            tournamentData = tournamentService.getTournament(id); // get updated tournament info
        } else { // tournament is over
            if (!tournamentData.isCalculated()) {
                Round last = tournamentData.getRounds().get(tournamentData.getTotalRounds() - 1);
                tournamentService.updateMatchResults(last);
                tournamentService.updateTournamentResults(last);
                tournamentService.endTournament(id);
            }
        }
        return new ResponseEntity<List<Round>>(tournamentData.getRounds(), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<HttpStatus> addTournament(@Valid @RequestBody Tournament tournament) {
        tournamentService.addTournament(tournament);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PutMapping("/{id}")
    public ResponseEntity<HttpStatus> updateTournamentById(@PathVariable Long id, @Valid @RequestBody Tournament newTournamentData) {
        tournamentService.updateTournament(id, newTournamentData);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<HttpStatus> deleteTournamentById(@PathVariable Long id) {
        tournamentService.deleteTournament(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @DeleteMapping("/{id}/user")
    public ResponseEntity<HttpStatus> withdraw(@RequestBody User user, @PathVariable Long id) {
        tournamentService.withdrawUser(user, id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/{id}/user")
    public ResponseEntity<HttpStatus> registerUser(@RequestBody User user, @PathVariable Long id) {
        tournamentService.registerUser(user, id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @GetMapping("/{id}/standings")
    public ResponseEntity<List<User>> getStandings(@PathVariable Long id) {
        List<User> users = tournamentService.getSortedUsers(id);
        return new ResponseEntity<List<User>>(users.subList(0, users.size() - 1), HttpStatus.OK); // excl bot
    }

    @GetMapping("/byElo/{elo}")
    public ResponseEntity<List<Tournament>> getTournamentByElo(@PathVariable int elo) {
        List<Tournament> t = tournamentService.getUserEligibleTournament(elo);
        return new ResponseEntity<List<Tournament>>(t, HttpStatus.OK);
    }

    @GetMapping("/byUser/{username}")
    public ResponseEntity<List<Tournament>> getHistoryByUser(@PathVariable String username) {
        List<Tournament> t = tournamentService.getHistoryByUser(username);
        return new ResponseEntity<List<Tournament>>(t, HttpStatus.OK);
    }

    @DeleteMapping("/user")
    public ResponseEntity<HttpStatus> deleteUser(@RequestBody User user) {
        tournamentService.deleteForUser(user);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}