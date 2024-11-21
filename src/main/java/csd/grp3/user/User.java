package csd.grp3.user;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;

import csd.grp3.usertournament.UserTournament;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.EqualsAndHashCode;

@Entity
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode
@Table(name = "AppUsers")

public class User implements UserDetails{
    private static final int DEFAULT_ELO = 100;

    private boolean suspicious = false;

    @Id @NotNull(message = "Username should not be null")
    private String username;

    @NotNull (message = "Password should not be null")
    @Size(min = 8, message = "Password should be at least 8 characters long")
    private String password;

    @NotNull(message = "Authorities should not be null")
    private String authorities;

    private Integer ELO = DEFAULT_ELO;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        this.authorities = "ROLE_USER";
    }

    public User(String username, String password, String authorities, int ELO) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
        this.ELO = ELO;
    }

    public String getUserRole() {
        return authorities;
    }

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL,orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonManagedReference(value = "userUserTournament") // Prevents infinite recursion
    private List<UserTournament> userTournaments = new ArrayList<>();
  
    // Return a collection of authorities (roles) granted to the user.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.asList(new SimpleGrantedAuthority(authorities));
    }
    
    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true; // Implement as needed
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true; // Implement as needed
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true; // Implement as needed
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true; // Implement as needed
    }

    public boolean isSuspicious() {
        return suspicious;
    }
}
