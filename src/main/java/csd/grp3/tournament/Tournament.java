package csd.grp3.tournament;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonManagedReference;

import csd.grp3.round.Round;
import csd.grp3.usertournament.UserTournament;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.EqualsAndHashCode;

@Entity
@Table(name="Tournaments")
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode

public class Tournament {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @OneToMany(mappedBy = "tournament", orphanRemoval = true, cascade = CascadeType.ALL)
    @JsonManagedReference // Prevents infinite recursion
    @ToString.Exclude
    private List<Round> rounds = new ArrayList<>();

    @NotNull(message = "Title: not null")
    private String title;

    @NotNull(message = "minElo: put a valid Elo")
    @Min(value = 0, message = "minElo: elo cannot be negative")
    private int minElo;

    @NotNull(message = "maxElo: put a valid Elo")
    @Min(value = 0, message = "maxElo: elo cannot be negative")
    private int maxElo;

    private LocalDateTime startDateTime;

    @NotNull(message = "size: put a valid tournament size")
    @Min(value = 2, message = "size: need at least 2 players")
    private int size;

    @NotNull(message = "totalRounds: put a valid number of rounds")
    @Min(value = 1, message = "totalRounds: need at least 1 round")
    private int totalRounds;

    private boolean isCalculated = false;

    public Tournament(String title, int minELO, int maxELO, LocalDateTime startDateTime, int size, int totalRounds) {
        this.title = title;
        this.minElo = minELO;
        this.maxElo = maxELO;
        this.startDateTime = startDateTime;
        this.size = size;
        this.totalRounds = totalRounds;
    }

    @OneToMany(mappedBy = "tournament", cascade = CascadeType.ALL,orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonManagedReference(value = "tournamentUserTournament") // Prevents infinite recursion
    private List<UserTournament> userTournaments = new ArrayList<>();

    public int getSize() {
        return size;
    }

    public int getDisplaySize() {
        return size - 1; // Subtract 1 to exclude the bot
    }

    public void setTotalRounds(int totalRounds) {
        this.totalRounds = totalRounds;

        // Check if the rounds list exceeds the new totalRounds limit
        if (this.rounds.size() > totalRounds) {
            // Shorten the rounds list to the new totalRounds limit
            this.rounds = new ArrayList<>(this.rounds.subList(0, totalRounds));
        }
    }

    public boolean isOver() {
        return rounds.size() == totalRounds && rounds.get(rounds.size() - 1).isOver();
    }

    public boolean hasStarted() {
        return LocalDateTime.now().isAfter(startDateTime) && userTournaments.size() > 1; // 2 Users + 1 Bot 
    }

    // Custom validation method
    @AssertTrue(message = "minElo must be less than maxElo")
    public boolean isMinEloLessThanMaxElo() {
        return minElo < maxElo;
    }
}