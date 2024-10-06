package csd.grp3.user;

import java.util.List;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

import jakarta.transaction.Transactional;

@Service
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder encoder ) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    //This function checks if password is alphanumeric and is 8 chars long
    private boolean checkPasswordRequirement(String password) {
    
        //Initialise booleans for password requirements
        boolean hasChar = false;
        boolean hasNum = false;
        boolean isAtLeast8Char = false;

        //Make password lowercase
        String tmpPassword = password.toLowerCase();

        //Check if password has char and num
        for (int i = 0; i < password.length(); i++) {
            char c = tmpPassword.charAt(i);
            if (c >= '0' && c <= '9') {
                hasNum = true;
            } else if (c >= 'a' && c <= 'z'){
                hasChar = true;
            }
        }

        //Check if password is at least 8 char long
        if (password.length() >= 8) {
            isAtLeast8Char = true;
        }
    
        //Print out error message
        if ((!hasChar || !hasNum) && isAtLeast8Char) {
            System.out.println("Password must contain both numbers and characters");
        } else if ((hasChar && hasNum) && !isAtLeast8Char) {
            System.out.println("Password must be at least 8 characters long");
        } else if ((!hasChar || !hasNum) && !isAtLeast8Char) {
            System.out.println("Password must contain both numbers and characters and be at least 8 characters long");
        } else {
            System.out.println("Password requirements met");
            return true;
        }

        return false;
    }

    public User createNewUser(String username, String password) throws UsernameAlreadyTakenException, WeakPasswordException{

        if (userRepository.findByUsername(username).isPresent()) {
            throw new UsernameAlreadyTakenException("Username already taken");
//System.out.println("Username already exists. Please choose another username");
        } else if (!checkPasswordRequirement(password)) {
            throw new WeakPasswordException("Password has to contain both characters and numbers and be at least 8 characters long");
//System.out.println("Does not meet password requirements");
        }
        //Encode password given by user to store
        String encodedPassword = encoder.encode(password);

        return userRepository.save(new User(username, encodedPassword));
    }

    public boolean login(String username, String password) throws InvalidCredentialsException{

        //If user does not exist, throw exception
        if (userRepository.findByUsername(username).isEmpty()) {
//System.out.println("USERNAME DOES NOT EXIST");
            throw new InvalidCredentialsException("Username does not exist");
        }

        //Get the password associated with the searched username
        User user = userRepository.findByUsername(username).get();
        String encodedPassword = user.getPassword();

        //Throw exception if password does not match
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        if (!encoder.matches(password, encodedPassword)) {
            throw new InvalidCredentialsException("Password does not match");
        }
        return true;
    }
    

    
    
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Override
    public User findByUsername(String username) throws UserNotFoundException{
        return userRepository.findByUsername(username)
        .orElseThrow(() -> new UserNotFoundException(username)); // Throw an exception if not found
    }
    
}
