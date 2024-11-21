package csd.grp3.user;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import csd.grp3.jwt.JwtService;
import jakarta.transaction.Transactional;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JwtService jwtService;

    /**
     * This method is used to find a user by their username
     * Throws a UsernameNotFoundException if the user is not found
     * 
     * @param username The username of the user to be found
     * @return The user with the given username
     */
    @Override
    public User findByUsername(String username) throws UsernameNotFoundException{
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }


    /**
     * This method is used to list all users in the database
     * 
     * @return A list of all users in the database
     */
    @Override
    public List<User> listUsers() {
        return userRepository.findAll();
    }


    /**
     * This method is used to create a new user
     * Throws a BadCredentialsException if the username already exists
     * 
     * @param username The username of the new user
     * @param password The password of the new user
     * @return The new user
     */
    @Override
    @Transactional
    public User createNewUser(String username, String password) throws BadCredentialsException{

        //Check if the username already exists, if it does throw exception
        if (userRepository.findByUsername(username).isPresent()) {
            throw new BadCredentialsException("Username already exists");
        }

        // Encode password given by user to store
        String encodedPassword = encoder.encode(password);

        return userRepository.save(new User(username, encodedPassword));
    }

    /**
     * This method is used to login a user
     * Throws a BadCredentialsException if the username and password do not match
     * 
     * @param username The username of the user to be logged in
     * @param password The password of the user to be logged in
     * @return The JWT token of the user
     */
    @Override
    public String login(String username, String password) throws BadCredentialsException{

        Authentication authentication = 
            authManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        //Return the user if the password matches
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken((UserDetails) authentication.getPrincipal());
        }
        //Else throw exception
        throw new BadCredentialsException("Username and Password do not match");
    }

    /**
     * This method is used to change the password of a user
     * Throws a UsernameNotFoundException if the user is not found
     * Throws a BadCredentialsException if the new password is the same as the old password
     * 
     * @param username The username of the user to change the password
     * @param newPassword The new password of the user
     * @return The user with the new password
     */
    @Override
    public User changePassword(String username, String newPassword) {
        User user = findByUsername(username);

        // If the new password is the same as the old one, throw an error
        if (encoder.matches(newPassword, user.getPassword())) {
            throw new BadCredentialsException("New password should not be the same as the old one");
        }
        
        user.setPassword(encoder.encode(newPassword));
        return userRepository.save(user);
    }

    /**
     * This method is used to delete a user by their username
     * 
     * @param username The username of the user to be deleted
     * @return The username of the deleted user
     */
    public String deleteByUsername(String username) {
        User user = findByUsername(username);
        userRepository.delete(user);
        return username;
    }

    /**
     * This method is used to update the ELO of a user
     * 
     * @param tempUser The user to update the ELO
     * @param ELO The new ELO of the user
     */
    @Override
    public void updateELO(User tempUser, int ELO) {
        User user = findByUsername(tempUser.getUsername());
        user.setELO(ELO);
        userRepository.save(user);
    }

    /**
     * This method is used to update the suspicious status of a user
     * 
     * @param tempUser The user to update the suspicious status
     * @param suspicious The new suspicious status of the user
     */
    @Override
    public void updateSuspicious(User tempUser, boolean suspicious) {
        User user = findByUsername(tempUser.getUsername());
        user.setSuspicious(suspicious);
        userRepository.save(user);
    }
}
