package csd.grp3.tournament;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

// import csd.grp3.match.MatchRepository;
// import csd.grp3.round.RoundRepository;
import csd.grp3.user.User;

import java.util.*;

@RestController
public class TournamentController {

//     @Autowired
//     private MatchRepository matchRepo;

//     @Autowired 
//     private RoundRepository roundRepo;

    @Autowired
    private TournamentRepository tournamentRepo;

    @Autowired
    private TournamentService tournamentService;

//     @GetMapping("/")
//     public String home() {
//         return "This is tournament system";
//     }

    @GetMapping("/tournaments")
    public ResponseEntity<List<Tournament>> getAllTournaments() {
        try {
            List<Tournament> tournamentList = new ArrayList<>();
            tournamentRepo.findAll().forEach(tournamentList::add);

            if (tournamentList.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NO_CONTENT).body(null);
            }

            return ResponseEntity.status(HttpStatus.OK).body(tournamentList);
        } catch (Exception ex) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/tournaments/{id}")
    public ResponseEntity<Tournament> getTournamentById(@PathVariable Long id) {
        Optional<Tournament> tournamentData = tournamentRepo.findById(id);

        if (tournamentData.isPresent()) {
            return new ResponseEntity<>(tournamentData.get(), HttpStatus.OK);
        }

        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    // @GetMapping("/tournaments/{title}")
    // public ResponseEntity<Tournament> getTournamentByTitle(@PathVariable String title) {
    //     Tournament tournamentData = tournamentRepo.findByTitle(title);
        
    //     if (tournamentData != null) {
    //         return new ResponseEntity<>(tournamentData, HttpStatus.OK);
    //     }

    //     return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    // }

//     @PostMapping("/tournaments")
//     @PreAuthorize("hasRole('ADMIN')")
//     public ResponseEntity<Tournament> addTournament(@RequestBody Tournament tournament) {
//         Tournament tournamentObj = tournamentRepo.save(tournament);

//         return new ResponseEntity<>(tournamentObj, HttpStatus.OK);
//     }

//     @PostMapping("/tournaments/{id}")
//     @PreAuthorize("hasRole('ADMIN')")
//     public ResponseEntity<Tournament> updateTournamentById(@PathVariable Long id, @RequestBody Tournament newTournamentData) {
//         Optional<Tournament> oldTournamentData = tournamentRepo.findById(id);

//         if (oldTournamentData.isPresent()) {
//             Tournament updatedTournamentData = oldTournamentData.get();
//             updatedTournamentData.setTitle(newTournamentData.getTitle());
//             updatedTournamentData.setDate(newTournamentData.getDate());
//             // updatedTournamentData.setMatches(newTournamentData.getMatches());
//             updatedTournamentData.setMaxElo(newTournamentData.getMaxElo());
//             // updatedTournamentData.setParticipants(newTournamentData.getParticipants());
//             updatedTournamentData.setMinElo(newTournamentData.getMinElo());
//             updatedTournamentData.setSize(newTournamentData.getSize());
//             updatedTournamentData.setWaitingList(newTournamentData.getWaitingList());

//             Tournament tournamentObj = tournamentRepo.save(updatedTournamentData);
//             return new ResponseEntity<>(tournamentObj, HttpStatus.OK);
//         }

//         return new ResponseEntity<>(HttpStatus.NOT_FOUND);
//     }

//     // @PostMapping("/tournaments/title/{title}")
//     // @PreAuthorize("hasRole('ADMIN')")
//     // public ResponseEntity<Tournament> updateTournamentByTitle(@PathVariable String title, @RequestBody Tournament newTournamentData) {
//     //     Tournament oldTournamentData = tournamentRepo.findByTitle(title);

//     //     if (oldTournamentData != null) {
//     //         Tournament updatedTournamentData = oldTournamentData;
//     //         updatedTournamentData.setTitle(newTournamentData.getTitle());
//     //         updatedTournamentData.setDate(newTournamentData.getDate());
//     //         // updatedTournamentData.setMatches(newTournamentData.getMatches());
//     //         updatedTournamentData.setMaxElo(newTournamentData.getMaxElo());
//     //         // updatedTournamentData.setParticipants(newTournamentData.getParticipants());
//     //         updatedTournamentData.setMinElo(newTournamentData.getMinElo());
//     //         updatedTournamentData.setSize(newTournamentData.getSize());
//     //         updatedTournamentData.setWaitingList(newTournamentData.getWaitingList());

//     //         Tournament tournamentObj = tournamentRepo.save(updatedTournamentData);
//     //         return new ResponseEntity<>(tournamentObj, HttpStatus.OK);
//     //     }

//     //     return new ResponseEntity<>(HttpStatus.NOT_FOUND);
//     // }

//     @DeleteMapping("/tournaments/{id}")
//     @PreAuthorize("hasRole('ADMIN')")
//     public ResponseEntity<HttpStatus> deleteTournamentById(@PathVariable Long id) {
//         tournamentRepo.deleteById(id);
//         return new ResponseEntity<>(HttpStatus.OK);
//     }

//     // @DeleteMapping("/tournaments/{title}")
//     // @PreAuthorize("hasRole('ADMIN')")
//     // public ResponseEntity<HttpStatus> deleteTournamentByTitle(@PathVariable String title) {
//     //     tournamentRepo.deleteByTitle(title);
//     //     return new ResponseEntity<>(HttpStatus.OK);
//     // }

    @PostMapping("/{id}/withdraw")
    public ResponseEntity<Void> withdrawPlayer(@RequestBody User player, @PathVariable Long id) {
        tournamentService.withdrawPlayer(player, id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/{id}/register")
    public ResponseEntity<Void> registerPlayer(@RequestBody User player, @PathVariable Long id) {
        tournamentService.registerPlayer(player, id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}
