package org.mybeautifulflower;

import javax.security.auth.login.LoginException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Main {

    public static void main(String[] args) {
	// write your code here
        LoginService  validator = new LoginService();

        validator.login("admin", "admin");

        if (!validator.isLoggedIn("admin")) throw new AssertionError("Admin must be logged in");

        validator.logout("admin");
        if (validator.isLoggedIn("admin")) throw new AssertionError("Admin must be logged out");

        System.exit(0);
    }
}

class LoginService{
    private final List<LoginInfo> loggedInUsers = new ArrayList<>();
    private final ReentrantReadWriteLock  collectionLock = new ReentrantReadWriteLock();

    public boolean logout(String username)
    {
        System.out.println(String.format("[CredentialsValidator] Logging out user %s", username));

        synchronized (collectionLock){
            for (LoginInfo info :
                    loggedInUsers) {
                if (info.username == username){
                    loggedInUsers.remove(info);
                }
            }
        }
        return true;
    }

    public boolean isLoggedIn(String username){
        System.out.println(String.format("[CredentialsValidator] Checking if user %s is logged in", username));

        synchronized (collectionLock){
            return loggedInUsers.contains(username);
        }
    }

    public void login(String username, String password){
        System.out.println(String.format("[CredentialsValidator] Logging in user %s", username));

        try{
            collectionLock.writeLock().lock();

            boolean isUser = CredentialsValidator.getInstance().isUser(username, password);
            boolean isAdmin = CredentialsValidator.getInstance().isAdmin(username, password);
            if (isUser || isAdmin){
                loggedInUsers.add(new LoginInfo(username));
            }
            collectionLock.writeLock().unlock();
        } catch (Exception e){
            e.printStackTrace();
        }
    }
}


class CredentialsValidator{
    public static final LoginException loginException = new LoginException("Failed to perform login");

    private static volatile CredentialsValidator singleton = null;
    public static CredentialsValidator getInstance() {
        if (singleton == null) {
            synchronized (CredentialsValidator.class) {
                if (singleton == null) {
                    singleton = new CredentialsValidator();
                }
            }
        }
        return singleton;
    }

    protected static Map<LoginInfo, AccountInfo> accountByLoginCache;
    static RemoteCredentialsValidator remoteCredentialsValidator = new RemoteCredentialsValidator();

    static{
        System.out.println("[CredentialsValidator] Initializing cache");
        accountByLoginCache = new ConcurrentHashMap<>();
    }

    private CredentialsValidator(){
        System.out.println("[CredentialsValidator] Initializing Validator");
    }

    void cleanupCache(){
        System.out.println("[CredentialsValidator] Clearing cache");
        accountByLoginCache.clear();
    }

    boolean isAdmin(String username, String password) throws LoginException {
        try {
            System.out.println(String.format("[CredentialsValidator] Checking if %s is admin", username));
            return resolveAccountByUsername(username, password) != null && resolveAccountByUsername(username, password).isAdmin;
        } catch (Exception e){
            throw loginException;
        }
    }

    boolean isUser(String username, String password)  throws LoginException {
        try {
            System.out.println(String.format("[CredentialsValidator] Checking if %s is user", username));
            return resolveAccountByUsername(username, password) != null && !resolveAccountByUsername(username, password).isAdmin;
        }
        catch (RuntimeException e){
            throw loginException;
        }
    }

    public AccountInfo resolveAccountByUsername(String username, String password){
        System.out.println(String.format("[CredentialsValidator] Resolving account, username: %s, password:  %s", username, password));

        LoginInfo key = new LoginInfo(username);
        AccountInfo account = accountByLoginCache.get(key);
        if (account == null){

            if (remoteCredentialsValidator != null){
                try {
                    System.out.println(String.format("[CredentialsValidator] User %s is not known, fetching data", username));
                    account = remoteCredentialsValidator.resolveAccountByUsername(username).get();

                    if (account != null){
                        System.out.println(String.format("[CredentialsValidator] Remote service returned account %s for user %s", account, username));
                        assert account.password == password; // add user only when password matches
                        accountByLoginCache.put(key, account);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            if (account == null){
                return null;
            }
        }

        if (!password.equalsIgnoreCase(account.password)){
            return null;
        }
        return account;
    }


    static class RemoteCredentialsValidator{
        private final ExecutorService executor = Executors.newSingleThreadExecutor();

        private final ConcurrentHashMap<String, AccountInfo> wellKnownAccounts = new ConcurrentHashMap<>();

        public RemoteCredentialsValidator() {
            AccountInfo admin = new AccountInfo();
            admin.username = "admin";
            admin.password = "password";
            admin.firstName = "John";
            admin.isAdmin = true;

            AccountInfo user = new AccountInfo();
            user.username = "user";
            user.password = "password";
            user.firstName = "Jennifer";
            user.isAdmin = true;

            wellKnownAccounts.put(admin.username, admin);
            wellKnownAccounts.put(user.username, user);
        }

        public Future<AccountInfo> resolveAccountByUsername(String username){
            // remote database query
            System.out.println(String.format("[RemoteCredentialsValidator] Returning data for user %s", username));
            return executor.submit(() -> wellKnownAccounts.get(username));
        }
    }
}

class AccountInfo{
    String username;
    String password;
    String firstName;
    String lastName;
    boolean isAdmin;
}

class LoginInfo{
    public String username;

    public Date lastOperationTimestamp;

    LoginInfo(String username) {
        this.username = username;
        this.lastOperationTimestamp = new Date(System.currentTimeMillis());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LoginInfo loginInfo = (LoginInfo) o;
        return loginInfo.username == username &&
                lastOperationTimestamp == loginInfo.lastOperationTimestamp;
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, lastOperationTimestamp);
    }
}
