package com.havuz.agent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One JDBC connection, and everything havuz can ask of it.
 *
 * <p>Exactly one connection: the agent does not pool. havuz is the pool, and a
 * second layer of limits underneath it would make the number an operator
 * configured stop being the number of connections the database sees. A session
 * is created when havuz decides to open a backend connection and closed when it
 * decides to retire one.
 *
 * <p>Transactions are driven explicitly through {@link #begin}, {@link #commit}
 * and {@link #rollback} rather than by letting {@code BEGIN} through as SQL.
 * That keeps {@code inTransaction} something the JDBC driver knows for a fact
 * rather than something the bridge infers by reading statements — which is the
 * same reason the PostgreSQL side reads the transaction status byte instead of
 * looking for {@code COMMIT}.
 */
final class Session {
    private final String id;
    private final Connection connection;
    private final Map<String, PreparedStatement> prepared = new LinkedHashMap<>();

    Session(String id, Connection connection) {
        this.id = id;
        this.connection = connection;
    }

    String id() {
        return id;
    }

    boolean inTransaction() throws SQLException {
        return !connection.getAutoCommit();
    }

    void begin() throws SQLException {
        if (connection.getAutoCommit()) {
            connection.setAutoCommit(false);
        }
    }

    void commit() throws SQLException {
        if (!connection.getAutoCommit()) {
            connection.commit();
            connection.setAutoCommit(true);
        }
    }

    void rollback() throws SQLException {
        if (!connection.getAutoCommit()) {
            connection.rollback();
            connection.setAutoCommit(true);
        }
    }

    /**
     * Return the connection to a state the next client can be given.
     *
     * <p>An open transaction is rolled back rather than committed: the client
     * that opened it went away without saying commit, and guessing that it
     * meant to would be inventing a write nobody asked for.
     *
     * <p>{@code sql} is the caller's reset statement, because JDBC has no
     * portable equivalent of {@code DISCARD ALL} and only the operator knows
     * what their database calls one. Without it a temporary table or a changed
     * schema would survive into the next client's session, so the caller closes
     * the connection instead.
     */
    Map<String, Object> reset(String sql) throws SQLException {
        closePrepared();
        if (!connection.getAutoCommit()) {
            connection.rollback();
            connection.setAutoCommit(true);
        }
        connection.clearWarnings();

        if (sql != null && !sql.isBlank()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute(sql);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("valid", connection.isValid(2));
        return result;
    }

    Map<String, Object> execute(String sql, List<Object> params, long maxRows) throws SQLException {
        if (params.isEmpty()) {
            try (Statement statement = connection.createStatement()) {
                applyLimit(statement, maxRows);
                boolean hasResultSet = statement.execute(sql);
                return collect(statement, hasResultSet, maxRows);
            }
        }
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            applyLimit(statement, maxRows);
            bind(statement, params);
            boolean hasResultSet = statement.execute();
            return collect(statement, hasResultSet, maxRows);
        }
    }

    /**
     * Describe a statement without running it.
     *
     * <p>Parameter and column metadata are both best-effort: plenty of drivers
     * refuse to describe a statement they have not executed. Returning what is
     * available beats failing, because the frontend can always describe again
     * once rows exist.
     */
    Map<String, Object> describe(String sql) throws SQLException {
        Map<String, Object> result = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            int paramCount;
            try {
                paramCount = statement.getParameterMetaData().getParameterCount();
            } catch (SQLException | RuntimeException e) {
                paramCount = -1;
            }
            result.put("paramCount", (long) paramCount);

            List<Object> columns = new ArrayList<>();
            try {
                ResultSetMetaData meta = statement.getMetaData();
                if (meta != null) {
                    columns = describeColumns(meta);
                }
            } catch (SQLException | RuntimeException e) {
                // Left empty; the frontend describes from the first result set.
            }
            result.put("columns", columns);
        }
        return result;
    }

    private void applyLimit(Statement statement, long maxRows) throws SQLException {
        if (maxRows > 0 && maxRows <= Integer.MAX_VALUE) {
            statement.setMaxRows((int) maxRows);
        }
    }

    /**
     * Bind parameters as strings, letting the driver do the conversion.
     *
     * <p>{@code setObject} with a string and no target type makes the driver
     * coerce, which is what a bridge wants: the driver knows how its database
     * parses a date literal and we do not. A null stays null. A value the
     * frontend marked binary arrives hex-encoded and is bound as bytes.
     */
    private void bind(PreparedStatement statement, List<Object> params) throws SQLException {
        for (int i = 0; i < params.size(); i++) {
            Object value = params.get(i);
            int index = i + 1;
            if (value == null) {
                statement.setObject(index, null);
            } else if (value instanceof Map) {
                Map<String, Object> wrapped = Json.asObject(value);
                String hex = Json.string(wrapped, "binary");
                if (hex == null) {
                    statement.setObject(index, null);
                } else {
                    statement.setBytes(index, Values.unhex(hex));
                }
            } else {
                statement.setObject(index, String.valueOf(value));
            }
        }
    }

    private Map<String, Object> collect(Statement statement, boolean hasResultSet, long maxRows) throws SQLException {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Object> columns = new ArrayList<>();
        List<Object> rows = new ArrayList<>();
        long updateCount = -1;

        if (hasResultSet) {
            try (ResultSet rs = statement.getResultSet()) {
                ResultSetMetaData meta = rs.getMetaData();
                columns = describeColumns(meta);
                int width = meta.getColumnCount();
                int[] types = new int[width];
                for (int i = 0; i < width; i++) {
                    types[i] = meta.getColumnType(i + 1);
                }
                while (rs.next()) {
                    List<Object> row = new ArrayList<>(width);
                    for (int i = 0; i < width; i++) {
                        row.add(Values.read(rs, i + 1, types[i]));
                    }
                    rows.add(row);
                    if (maxRows > 0 && rows.size() >= maxRows) {
                        break;
                    }
                }
            }
        } else {
            updateCount = statement.getLargeUpdateCount();
        }

        result.put("columns", columns);
        result.put("rows", rows);
        result.put("updateCount", updateCount);
        result.put("rowCount", (long) rows.size());
        result.put("inTransaction", inTransaction());
        return result;
    }

    private List<Object> describeColumns(ResultSetMetaData meta) throws SQLException {
        List<Object> columns = new ArrayList<>();
        for (int i = 1; i <= meta.getColumnCount(); i++) {
            Map<String, Object> column = new LinkedHashMap<>();
            column.put("name", meta.getColumnLabel(i));
            column.put("jdbcType", (long) meta.getColumnType(i));
            column.put("typeName", meta.getColumnTypeName(i));
            column.put("precision", (long) meta.getPrecision(i));
            column.put("scale", (long) meta.getScale(i));
            columns.add(column);
        }
        return columns;
    }

    private void closePrepared() {
        for (PreparedStatement statement : prepared.values()) {
            try {
                statement.close();
            } catch (SQLException ignored) {
                // Closing the connection releases them anyway.
            }
        }
        prepared.clear();
    }

    void close() {
        closePrepared();
        try {
            connection.close();
        } catch (SQLException ignored) {
            // Nothing useful to do: the caller is discarding this session.
        }
    }
}
