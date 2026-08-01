package com.havuz.agent;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Newline-delimited JSON-RPC over stdio.
 *
 * <p>One process serves many sessions. That is not an optimisation so much as a
 * necessity: a JVM costs tens of megabytes and hundreds of milliseconds to
 * start, and a pooler that paid that per backend connection would be slower
 * than not pooling at all.
 *
 * <p>Requests are handled one at a time, in order. Concurrency lives in havuz,
 * which decides how many backend connections exist and hands each to one client
 * at a time; adding a thread pool here would buy nothing and would make the
 * failure modes considerably harder to reason about.
 */
public final class Agent {
    /** Bumped when the message shapes change incompatibly. */
    private static final int PROTOCOL = 1;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicLong nextSession = new AtomicLong(1);
    private final Map<String, ClassLoader> loaders = new ConcurrentHashMap<>();
    private final PrintStream out;
    private volatile boolean running = true;

    private Agent(PrintStream out) {
        this.out = out;
    }

    public static void main(String[] args) throws Exception {
        // stdout is the protocol. Anything a driver prints there would corrupt
        // it, so the real stream is captured first and System.out is redirected
        // to stderr before any driver class is loaded.
        PrintStream protocol = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), false,
                StandardCharsets.UTF_8);
        System.setOut(new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err), true,
                StandardCharsets.UTF_8));

        Agent agent = new Agent(protocol);
        agent.announce();
        agent.run();
    }

    /**
     * Say we are up before any request arrives.
     *
     * <p>JVM startup is slow enough that the parent needs to tell "still
     * booting" from "wedged", and a readiness line is the cheapest way to do
     * it that does not involve a timeout guessing game.
     */
    private void announce() {
        Map<String, Object> ready = new LinkedHashMap<>();
        ready.put("ready", true);
        ready.put("protocol", (long) PROTOCOL);
        emit(ready);
    }

    private void run() throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while (running && (line = reader.readLine()) != null) {
            if (line.isBlank()) {
                continue;
            }
            handle(line);
        }
        shutdown();
    }

    private void handle(String line) {
        Object id = null;
        try {
            Map<String, Object> request = Json.asObject(Json.parse(line));
            id = request.get("id");
            String method = Json.string(request, "method");
            Map<String, Object> params = Json.asObject(request.get("params"));
            Object result = dispatch(method, params);
            respond(id, result, null);
        } catch (Throwable e) {
            // Throwable, not Exception: a driver that throws NoClassDefFoundError
            // must produce a diagnosable error rather than a silent hang.
            respond(id, null, describe(e));
        }
    }

    private Object dispatch(String method, Map<String, Object> params) throws Exception {
        if (method == null) {
            throw new IllegalArgumentException("request has no method");
        }
        switch (method) {
            case "handshake":
                return handshake();
            case "open_session":
                return openSession(params);
            case "execute":
                return session(params).execute(Json.string(params, "sql"), Json.asArray(params.get("params")),
                        Json.number(params, "maxRows", 0));
            case "describe":
                return session(params).describe(Json.string(params, "sql"));
            case "begin":
                session(params).begin();
                return transactionState(session(params));
            case "commit":
                session(params).commit();
                return transactionState(session(params));
            case "rollback":
                session(params).rollback();
                return transactionState(session(params));
            case "reset":
                return session(params).reset(Json.string(params, "sql"));
            case "close_session":
                return closeSession(params);
            case "shutdown":
                running = false;
                return new LinkedHashMap<String, Object>();
            default:
                throw new IllegalArgumentException("unknown method '" + method + "'");
        }
    }

    private Map<String, Object> handshake() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("protocol", (long) PROTOCOL);
        result.put("java", System.getProperty("java.version"));
        result.put("vendor", System.getProperty("java.vendor"));
        return result;
    }

    private Map<String, Object> openSession(Map<String, Object> params) throws SQLException {
        String url = require(params, "url");
        String driverClass = Json.string(params, "driverClass");
        List<Object> driverPaths = Json.asArray(params.get("driverPaths"));

        Properties properties = new Properties();
        putIfPresent(properties, "user", Json.string(params, "user"));
        putIfPresent(properties, "password", Json.string(params, "password"));
        for (Map.Entry<String, Object> entry : Json.asObject(params.get("properties")).entrySet()) {
            if (entry.getValue() != null) {
                properties.setProperty(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }

        long connectTimeout = Json.number(params, "connectTimeoutMs", 0);
        if (connectTimeout > 0) {
            DriverManager.setLoginTimeout((int) Math.max(1, connectTimeout / 1000));
        }

        Connection connection = connect(url, properties, driverClass, driverPaths);
        try {
            connection.setAutoCommit(true);
        } catch (SQLException ignored) {
            // Some drivers are always autocommit and refuse to be told so.
        }

        String id = "s" + nextSession.getAndIncrement();
        sessions.put(id, new Session(id, connection));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("session", id);
        result.put("inTransaction", false);
        try {
            result.put("serverVersion", connection.getMetaData().getDatabaseProductVersion());
            result.put("serverName", connection.getMetaData().getDatabaseProductName());
        } catch (SQLException e) {
            result.put("serverVersion", "unknown");
            result.put("serverName", "unknown");
        }
        return result;
    }

    /**
     * Open a connection, loading a user-supplied driver if one was named.
     *
     * <p>Class loaders are cached per classpath. Building a new one per
     * connection would reload the driver's classes every time, which leaks
     * metaspace and, for some drivers, static state.
     */
    private Connection connect(String url, Properties properties, String driverClass, List<Object> driverPaths)
            throws SQLException {
        if (driverPaths.isEmpty() && driverClass == null) {
            return DriverManager.getConnection(url, properties);
        }

        String key = driverClass + "\u001f" + String.join("\u001f", strings(driverPaths));
        ClassLoader loader = loaders.computeIfAbsent(key, ignored -> buildLoader(driverPaths));

        Driver driver = resolveDriver(loader, driverClass, url);
        if (driver == null) {
            throw new SQLException("no JDBC driver in the supplied classpath accepts '" + url + "'");
        }
        Connection connection = driver.connect(url, properties);
        if (connection == null) {
            throw new SQLException("driver " + driver.getClass().getName() + " declined the URL '" + url + "'");
        }
        return connection;
    }

    private ClassLoader buildLoader(List<Object> driverPaths) {
        List<URL> urls = new ArrayList<>();
        for (String path : strings(driverPaths)) {
            try {
                urls.add(new File(path).toURI().toURL());
            } catch (Exception e) {
                throw new IllegalArgumentException("bad driver path '" + path + "': " + e.getMessage());
            }
        }
        return new URLClassLoader(urls.toArray(new URL[0]), Agent.class.getClassLoader());
    }

    private Driver resolveDriver(ClassLoader loader, String driverClass, String url) throws SQLException {
        if (driverClass != null && !driverClass.isBlank()) {
            try {
                Object instance = Class.forName(driverClass, true, loader).getDeclaredConstructor().newInstance();
                Driver driver = new DriverShim((Driver) instance);
                DriverManager.registerDriver(driver);
                return driver;
            } catch (ReflectiveOperationException e) {
                throw new SQLException("cannot load driver class '" + driverClass + "': " + e, e);
            }
        }
        // No class named: fall back to whatever the JAR advertises.
        for (Driver candidate : ServiceLoader.load(Driver.class, loader)) {
            if (candidate.acceptsURL(url)) {
                Driver driver = new DriverShim(candidate);
                DriverManager.registerDriver(driver);
                return driver;
            }
        }
        return null;
    }

    private Map<String, Object> closeSession(Map<String, Object> params) {
        String id = Json.string(params, "session");
        Session session = id == null ? null : sessions.remove(id);
        if (session != null) {
            session.close();
        }
        return new LinkedHashMap<>();
    }

    private void shutdown() {
        for (Session session : sessions.values()) {
            session.close();
        }
        sessions.clear();
    }

    private Session session(Map<String, Object> params) throws SQLException {
        String id = Json.string(params, "session");
        Session session = id == null ? null : sessions.get(id);
        if (session == null) {
            throw new SQLException("unknown session '" + id + "'");
        }
        return session;
    }

    private Map<String, Object> transactionState(Session session) throws SQLException {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("inTransaction", session.inTransaction());
        return result;
    }

    // --- protocol plumbing ---

    private void respond(Object id, Object result, Map<String, Object> error) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        response.put("id", id);
        if (error != null) {
            response.put("error", error);
        } else {
            response.put("result", result == null ? new LinkedHashMap<String, Object>() : result);
        }
        emit(response);
    }

    /**
     * One document per line, flushed immediately.
     *
     * <p>Buffering would let a response sit in the pipe while the parent waits
     * for it, which looks exactly like a hung database.
     */
    private synchronized void emit(Map<String, Object> document) {
        out.print(Json.write(document));
        out.print('\n');
        out.flush();
    }

    /**
     * Turn a Java exception into something an operator can act on.
     *
     * <p>The SQLSTATE is carried through when the driver supplied one, because
     * it is the only part of a JDBC error with an agreed meaning, and the
     * frontend maps it onto the error its own protocol uses.
     */
    private Map<String, Object> describe(Throwable e) {
        Map<String, Object> error = new LinkedHashMap<>();
        String message = e.getMessage();
        error.put("message", message == null || message.isBlank() ? e.toString() : message);
        error.put("class", e.getClass().getName());
        if (e instanceof SQLException sql) {
            if (sql.getSQLState() != null) {
                error.put("sqlState", sql.getSQLState());
            }
            error.put("vendorCode", (long) sql.getErrorCode());
        }
        return error;
    }

    private static String require(Map<String, Object> params, String key) {
        String value = Json.string(params, key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing required parameter '" + key + "'");
        }
        return value;
    }

    private static void putIfPresent(Properties properties, String key, String value) {
        if (value != null) {
            properties.setProperty(key, value);
        }
    }

    private static List<String> strings(List<Object> values) {
        List<String> out = new ArrayList<>(values.size());
        for (Object value : values) {
            if (value != null) {
                out.add(String.valueOf(value));
            }
        }
        return out;
    }
}
