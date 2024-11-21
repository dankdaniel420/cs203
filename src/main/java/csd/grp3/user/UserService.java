package csd.grp3.user;

import java.util.List;

public interface UserService {
    User createNewUser(String username, String password);
    String login(String username, String password);
    User findByUsername(String username);
    User changePassword(String username, String password);
    String deleteByUsername(String username);
    void updateELO(User user, int ELO);
    List<User> listUsers();
    void updateSuspicious(User user, boolean suspicious);
}
