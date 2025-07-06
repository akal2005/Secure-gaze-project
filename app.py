// Java-based backend (Spring Boot) for graphical password authentication

// ------------------------------
// User Entity Class
// ------------------------------
import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    private String fullName;
    private String bio;
    private String profilePic;

    @Column(nullable = false)
    private String graphicalPasswordHash;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }

    public String getBio() { return bio; }
    public void setBio(String bio) { this.bio = bio; }

    public String getProfilePic() { return profilePic; }
    public void setProfilePic(String profilePic) { this.profilePic = profilePic; }

    public String getGraphicalPasswordHash() { return graphicalPasswordHash; }
    public void setGraphicalPasswordHash(String graphicalPasswordHash) { this.graphicalPasswordHash = graphicalPasswordHash; }
}

// ------------------------------
// User Repository
// ------------------------------
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}

// ------------------------------
// Graphical Password Utility
// ------------------------------
import java.util.*;

public class GraphicalPasswordUtil {
    public static final String[] CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("");

    public static final String[] COLORS = {
        "#FF0000", "#00FF00", "#0000FF", "#FFFF00", "#FF00FF", "#00FFFF",
        "#FFA500", "#800080", "#008000", "#FFC0CB", "#A52A2A", "#FFD700",
        "#FF4500", "#DA70D6", "#7FFF00", "#4682B4", "#FF69B4", "#9ACD32",
        "#20B2AA", "#9932CC", "#FFDAB9", "#00CED1", "#FF6347", "#ADFF2F",
        "#BA55D3", "#98FB98", "#F08080", "#7B68EE", "#FFE4B5", "#40E0D0",
        "#C71585", "#66CDAA", "#FFDEAD", "#00FA9A", "#DC143C", "#F0E68C",
        "#6495ED", "#FFF0F5", "#228B22", "#DAA520", "#6A5ACD", "#F5DEB3",
        "#4169E1", "#FA8072", "#2E8B57", "#EEE8AA", "#B22222", "#87CEEB",
        "#9400D3", "#F4A460", "#6B8E23", "#FFB6C1", "#483D8B", "#FF8C00",
        "#90EE90", "#BC8F8F", "#8B008B", "#556B2F", "#FFEBCD", "#1E90FF",
        "#FFFACD", "#D2691E"
    };

    public static Map<String, Character> getColorToChar() {
        Map<String, Character> map = new HashMap<>();
        for (int i = 0; i < CHARACTERS.length; i++) {
            map.put(COLORS[i], CHARACTERS[i].charAt(0));
        }
        return map;
    }
}

// ------------------------------
// Authentication Controller
// ------------------------------
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import jakarta.servlet.http.HttpSession;
import java.util.*;

@Controller
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String email,
                           @RequestParam String fullName,
                           @RequestParam String graphicalPasswordJson,
                           RedirectAttributes redirectAttrs) {
        try {
            String decodedPassword = decodeGraphicalPassword(graphicalPasswordJson);
            String hashedPassword = new BCryptPasswordEncoder().encode(decodedPassword);

            User user = new User();
            user.setUsername(username);
            user.setEmail(email);
            user.setFullName(fullName);
            user.setGraphicalPasswordHash(hashedPassword);

            userRepository.save(user);
            redirectAttrs.addFlashAttribute("success", "Registration successful!");
        } catch (Exception e) {
            redirectAttrs.addFlashAttribute("error", "Error: " + e.getMessage());
        }
        return "redirect:/login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String graphicalPasswordJson,
                        HttpSession session,
                        RedirectAttributes redirectAttrs) {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            redirectAttrs.addFlashAttribute("error", "Invalid username");
            return "redirect:/login";
        }

        User user = optionalUser.get();
        String decodedPassword = decodeGraphicalPassword(graphicalPasswordJson);

        if (new BCryptPasswordEncoder().matches(decodedPassword, user.getGraphicalPasswordHash())) {
            session.setAttribute("userId", user.getId());
            return "redirect:/dashboard";
        } else {
            redirectAttrs.addFlashAttribute("error", "Invalid graphical password");
            return "redirect:/login";
        }
    }

    private String decodeGraphicalPassword(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        List<List<String>> pairs = mapper.readValue(json, new TypeReference<List<List<String>>>() {});
        Map<String, Character> colorToChar = GraphicalPasswordUtil.getColorToChar();

        StringBuilder password = new StringBuilder();
        for (List<String> pair : pairs) {
            password.append(colorToChar.get(pair.get(0)));
            password.append(colorToChar.get(pair.get(1)));
        }
        return password.toString();
    }
}
