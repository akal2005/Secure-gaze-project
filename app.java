import java.util.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharset;

public class GraphicalAuthSystem {

    // ------------------------------------------------------------
    // USER MODEL 
    // ------------------------------------------------------------
    static class User {
        private Long id;
        private String username;
        private String email;
        private String fullName;
        private String bio;
        private String profilePic;
        private String graphicalPasswordHash;

        public User(Long id, String username, String email, String fullName, String hash) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.fullName = fullName;
            this.graphicalPasswordHash = hash;
        }

        public Long getId() { return id; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getFullName() { return fullName; }
        public String getGraphicalPasswordHash() { return graphicalPasswordHash; }
    }

    // ------------------------------------------------------------
    // IN-MEMORY "DATABASE"
    // ------------------------------------------------------------
    static class UserDatabase {
        private Map<String, User> users = new HashMap<>();
        private Long counter = 1L;

        public void save(User user) {
            users.put(user.getUsername(), user);
        }

        public User findByUsername(String username) {
            return users.get(username);
        }

        public Long nextId() {
            return counter++;
        }
    }

    // ------------------------------------------------------------
    // GRAPHICAL PASSWORD UTILITY
    // ------------------------------------------------------------
    static class GraphicalPasswordUtil {

        public static final String[] CHARACTERS =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("");

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

        // Map color → character
        public static Map<String, Character> getColorToCharacterMap() {
            Map<String, Character> map = new HashMap<>();
            for (int i = 0; i < CHARACTERS.length; i++) {
                map.put(COLORS[i], CHARACTERS[i].charAt(0));
            }
            return map;
        }

        // Convert pairs of [color1, color2] to decrypted password
        public static String decodeGraphicalPassword(List<List<String>> pairs) {
            Map<String, Character> map = getColorToCharacterMap();
            StringBuilder sb = new StringBuilder();

            for (List<String> pair : pairs) {
                sb.append(map.get(pair.get(0)));
                sb.append(map.get(pair.get(1)));
            }

            return sb.toString();
        }

        // SHA-256 HASH FUNCTION
        public static String hashPassword(String password) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder();
                for (byte b : hash) {
                    hex.append(String.format("%02x", b));
                }
                return hex.toString();
            } catch (Exception e) {
                throw new RuntimeException("Hashing error");
            }
        }
    }

    // ------------------------------------------------------------
    // AUTHENTICATION SERVICE
    // ------------------------------------------------------------
    static class AuthService {
        UserDatabase db;

        public AuthService(UserDatabase db) {
            this.db = db;
        }

        // REGISTER USER
        public String register(String username, String email, String fullName, List<List<String>> passwordPairs) {

            String decoded = GraphicalPasswordUtil.decodeGraphicalPassword(passwordPairs);
            String hashed = GraphicalPasswordUtil.hashPassword(decoded);

            User user = new User(db.nextId(), username, email, fullName, hashed);
            db.save(user);

            return "Registration successful!";
        }

        // LOGIN USER
        public String login(String username, List<List<String>> passwordPairs) {

            User user = db.findByUsername(username);
            if (user == null) return "Error: User not found";

            String decoded = GraphicalPasswordUtil.decodeGraphicalPassword(passwordPairs);
            String hashed = GraphicalPasswordUtil.hashPassword(decoded);

            if (hashed.equals(user.getGraphicalPasswordHash())) {
                return "Login successful! Welcome, " + user.getFullName();
            } else {
                return "Error: Invalid graphical password";
            }
        }
    }

    // ------------------------------------------------------------
    // MAIN METHOD TO RUN PROGRAM
    // ------------------------------------------------------------
    public static void main(String[] args) {

        UserDatabase db = new UserDatabase();
        AuthService auth = new AuthService(db);

        // EXAMPLE: Graphical password input
        List<List<String>> gp = new ArrayList<>();
        gp.add(Arrays.asList("#FF0000", "#00FF00")); // red + green
        gp.add(Arrays.asList("#0000FF", "#FFFF00")); // blue + yellow

        // Registration
        System.out.println(auth.register("john123", "john@gmail.com", "John Doe", gp));

        // Login
        System.out.println(auth.login("john123", gp));
    }
}
