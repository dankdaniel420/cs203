package csd.grp3.CheaterBugAPI;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

import java.util.List;

@RestController
@RequestMapping("/cheaterbug")
public class CheaterbugController {

    private final CheaterbugService cheaterbugService;

    public CheaterbugController(CheaterbugService cheaterbugService) {
        this.cheaterbugService = cheaterbugService;
    }

    @PostMapping("/analysis")
    public ResponseEntity<CheaterbugResponse> analyze(
            @Valid @RequestBody List<CheaterbugEntity> request) {
        CheaterbugResponse response = cheaterbugService.analyze(request);
        return ResponseEntity.ok(response);
    }
}
