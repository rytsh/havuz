package com.havuz.agent;

import java.math.BigDecimal;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLXML;
import java.sql.Types;

/**
 * One JDBC value, as a canonical string or null.
 *
 * <p>The default is {@link ResultSet#getString}, and that is a deliberate
 * choice rather than laziness. A JDBC driver already knows how its database
 * renders its own types, including the vendor types nobody outside that vendor
 * has heard of. Reaching for typed getters and reformatting by hand replaces
 * that knowledge with our guess, and the guess is wrong first for exactly the
 * long-tail databases this bridge exists to reach.
 *
 * <p>Three exceptions, each for a concrete reason:
 *
 * <ul>
 *   <li><b>Binary</b> — {@code getString} on a byte array is undefined at best
 *       and mojibake at worst. Read the bytes, render as hex, let the frontend
 *       add whatever prefix its protocol wants.
 *   <li><b>Boolean</b> — every database spells it differently: {@code t},
 *       {@code 1}, {@code TRUE}, {@code Y}. A bridge that passes those through
 *       makes the client's behaviour depend on which database it reached.
 *   <li><b>Decimal</b> — {@code getString} is allowed to use the JVM's locale,
 *       and a comma decimal separator would silently corrupt every number.
 *       {@code toPlainString} is also the only rendering that never switches to
 *       scientific notation.
 * </ul>
 */
final class Values {
    private Values() {}

    /** Column {@code index} of the current row, one-based, or null. */
    static String read(ResultSet rs, int index, int jdbcType) throws SQLException {
        String value = readRaw(rs, index, jdbcType);
        // Checked after the read, never before: a primitive getter returns 0 or
        // false for SQL NULL, and reporting that as a value would be a silent
        // data corruption rather than a visible failure.
        return rs.wasNull() ? null : value;
    }

    private static String readRaw(ResultSet rs, int index, int jdbcType) throws SQLException {
        switch (jdbcType) {
            case Types.BINARY:
            case Types.VARBINARY:
            case Types.LONGVARBINARY:
                return hex(rs.getBytes(index));

            case Types.BLOB: {
                Blob blob = rs.getBlob(index);
                if (blob == null) {
                    return null;
                }
                try {
                    long length = blob.length();
                    if (length > MAX_LOB_BYTES) {
                        throw new SQLException("BLOB of " + length + " bytes exceeds the agent's limit");
                    }
                    return hex(blob.getBytes(1, (int) length));
                } finally {
                    freeQuietly(blob);
                }
            }

            case Types.BOOLEAN:
            case Types.BIT:
                return rs.getBoolean(index) ? "true" : "false";

            case Types.DECIMAL:
            case Types.NUMERIC: {
                BigDecimal decimal = rs.getBigDecimal(index);
                return decimal == null ? null : decimal.toPlainString();
            }

            case Types.CLOB:
            case Types.NCLOB: {
                Clob clob = rs.getClob(index);
                if (clob == null) {
                    return null;
                }
                try {
                    long length = clob.length();
                    if (length > MAX_LOB_BYTES) {
                        throw new SQLException("CLOB of " + length + " characters exceeds the agent's limit");
                    }
                    return clob.getSubString(1, (int) length);
                } finally {
                    freeQuietly(clob);
                }
            }

            case Types.SQLXML: {
                SQLXML xml = rs.getSQLXML(index);
                return xml == null ? null : xml.getString();
            }

            default:
                return rs.getString(index);
        }
    }

    /**
     * A single value is capped rather than streamed.
     *
     * <p>Streaming would mean holding the JDBC connection across many frontend
     * writes, and a pooler's whole job is to decide when that connection is
     * given back. A refused 200 MB blob is a clear error; a pool that silently
     * stops multiplexing is not.
     */
    private static final long MAX_LOB_BYTES = 64L * 1024 * 1024;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** Lower-case hex, no prefix. The frontend adds what its protocol wants. */
    static String hex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = HEX[(bytes[i] >> 4) & 0x0f];
            out[i * 2 + 1] = HEX[bytes[i] & 0x0f];
        }
        return new String(out);
    }

    static byte[] unhex(String text) {
        int length = text.length() / 2;
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void freeQuietly(Blob blob) {
        try {
            blob.free();
        } catch (SQLException | UnsupportedOperationException ignored) {
            // Some drivers do not implement free(); the connection close will
            // release it. Not worth failing a successful query over.
        }
    }

    private static void freeQuietly(Clob clob) {
        try {
            clob.free();
        } catch (SQLException | UnsupportedOperationException ignored) {
            // As above.
        }
    }
}
