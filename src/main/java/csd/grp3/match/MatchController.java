package csd.grp3.match;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
public class MatchController {

    private MatchService matchService;

    /**
     * Updates match details of matches in list, saves updates to repository
     * 
     * @param matches List of match object to be updated
     * @return List of matches updated
     */
    @PutMapping("/matches")
    public List<Match> updateMatches(@Valid @RequestBody List<Match> matches) {
        List<Match> updatedList = new ArrayList<>();
        for (Match match : matches) {
            updatedList.add(matchService.updateMatch(match.getId(), match));
        }
        return updatedList;
    }
}