package org.mybeautifulflower;

import javax.security.auth.login.LoginException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Main {

    public static void main(String[] args) {
        LoginService  validator = new LoginService();
        validator.login("admin", "password");
        if (!validator.isLoggedIn("admin")) throw new AssertionError("Admin must be logged in");
        validator.logout("admin");
        if (validator.isLoggedIn("admin")) throw new AssertionError("Admin must be logged out");
        System.out.print("All good !");
        System.exit(0);
    }
}

class LoginService{
    private final List<LoginInfo> loggedInUsers = new ArrayList<>();
    private final ReentrantReadWriteLock  collectionLock = new ReentrantReadWriteLock();

    public void logout(String username)
    {
        System.out.printf("[CredentialsValidator] Logging out user %s%n", username);

        synchronized (collectionLock){
            loggedInUsers.removeIf(info -> info.username.equals(username));
        }
    }

    public boolean isLoggedIn(String username){
        System.out.printf("[CredentialsValidator] Checking if user %s is logged in%n", username);

        synchronized (collectionLock){
            for (LoginInfo user : loggedInUsers) {
                if (Objects.equals(user, username)){
                    return true;
                }
            }
        }
        return false;
    }

    public void login(String username, String password){
        System.out.printf("[CredentialsValidator] Logging in user %s%n", username);

        try{
            collectionLock.writeLock().lock();

            boolean isUser = CredentialsValidator.getSingleton().isUser(username, password);
            boolean isAdmin = CredentialsValidator.getSingleton().isAdmin(username, password);
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
    protected static Map<LoginInfo, AccountInfo> accountByLoginCache;
    private static volatile CredentialsValidator singleton = null;
    static RemoteCredentialsValidator remoteCredentialsValidator = new RemoteCredentialsValidator();

    public static CredentialsValidator getSingleton() {
        if (singleton == null) {
            singleton = new CredentialsValidator();
        }
        return singleton;
    }


    static{
        System.out.println("[CredentialsValidator] Initializing cache");
        accountByLoginCache = new ConcurrentHashMap<>();
    }

    private CredentialsValidator(){
        System.out.println("[CredentialsValidator] Initializing Validator");
    }

    boolean isAdmin(String username, String password) throws LoginException {
        try {
            System.out.printf("[CredentialsValidator] Checking if %s is admin%n", username);
            return resolveAccountByUsername(username, password) != null && resolveAccountByUsername(username, password).isAdmin;
        } catch (Exception e){
            throw loginException;
        }
    }

    boolean isUser(String username, String password)  throws LoginException {
        try {
            System.out.printf("[CredentialsValidator] Checking if %s is user%n", username);
            return resolveAccountByUsername(username, password) != null && !resolveAccountByUsername(username, password).isAdmin;
        }
        catch (RuntimeException e){
            throw loginException;
        }
    }

    public AccountInfo resolveAccountByUsername(String username, String password) {
        System.out.printf("[CredentialsValidator] Resolving account, username: %s, password:  %s%n", username, password);

        LoginInfo key = new LoginInfo(username);
        AccountInfo account = accountByLoginCache.get(key);
        if (account == null){
            System.out.printf("[CredentialsValidator] User %s is not known, fetching data%n", username);
            account = remoteCredentialsValidator.resolveAccountByUsername(username);

            if (account != null){
                System.out.printf("[CredentialsValidator] Remote service returned account %s for user %s%n", account, username);
                accountByLoginCache.put(key, account);
            }
        }

        if (account == null || !password.equalsIgnoreCase(account.password)){
            return null;
        }
        return account;
    }

    static class RemoteCredentialsValidator{
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

        public AccountInfo resolveAccountByUsername(String username){
            // remote database query
            System.out.printf("[RemoteCredentialsValidator] Returning data for user %s%n", username);
            return wellKnownAccounts.get(username);
        }
    }
}

class AccountInfo{
    String username;
    String password;
    String firstName;
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
        return Objects.equals(username, loginInfo.username) &&
                Objects.equals(lastOperationTimestamp, loginInfo.lastOperationTimestamp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, lastOperationTimestamp);
    }
}
