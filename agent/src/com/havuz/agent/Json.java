package com.havuz.agent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Just enough JSON, so the agent has no dependencies.
 *
 * <p>The message set is fixed and narrow — a handful of objects with string,
 * number, boolean, null and array members — so pulling in Jackson or Gson would
 * add a dependency tree and a build system to save a couple of hundred lines.
 *
 * <p>Values are represented with plain JDK types: {@code Map<String,Object>},
 * {@code List<Object>}, {@code String}, {@code Double}, {@code Long},
 * {@code Boolean}, {@code null}. There is no object mapping and no reflection.
 *
 * <p>What this deliberately does not do: reject duplicate keys, preserve number
 * formatting, or handle anything outside RFC 8259. It reads what havuz writes
 * and writes what havuz reads.
 */
final class Json {
    private Json() {}

    // --- writing ---

    static void write(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            writeString(out, (String) value);
        } else if (value instanceof Boolean) {
            out.append(value.toString());
        } else if (value instanceof Integer || value instanceof Long) {
            out.append(value.toString());
        } else if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            // Infinity and NaN are not JSON. Emitting them would produce a
            // document the parent cannot parse, which is worse than a null.
            out.append(Double.isFinite(d) ? Double.toString(d) : "null");
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, item);
            }
            out.append(']');
        } else {
            writeString(out, value.toString());
        }
    }

    static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    private static void writeString(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    // Control characters must be escaped; the rest goes out as
                    // UTF-8, including anything above the BMP as surrogates.
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // --- reading ---

    static Object parse(String input) {
        Parser parser = new Parser(input);
        parser.skipWhitespace();
        Object value = parser.value();
        parser.skipWhitespace();
        if (!parser.done()) {
            throw new IllegalArgumentException("trailing content at offset " + parser.pos);
        }
        return value;
    }

    private static final class Parser {
        private final String input;
        private int pos;

        Parser(String input) {
            this.input = input;
        }

        boolean done() {
            return pos >= input.length();
        }

        void skipWhitespace() {
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object value() {
            if (done()) {
                throw new IllegalArgumentException("unexpected end of input");
            }
            char c = input.charAt(pos);
            return switch (c) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Object literal(String text, Object value) {
            if (!input.startsWith(text, pos)) {
                throw new IllegalArgumentException("bad literal at offset " + pos);
            }
            pos += text.length();
            return value;
        }

        private Map<String, Object> object() {
            Map<String, Object> out = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return out;
            }
            while (true) {
                skipWhitespace();
                String key = string();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                out.put(key, value());
                skipWhitespace();
                char c = next();
                if (c == '}') {
                    return out;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected ',' or '}' at offset " + (pos - 1));
                }
            }
        }

        private List<Object> array() {
            List<Object> out = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return out;
            }
            while (true) {
                skipWhitespace();
                out.add(value());
                skipWhitespace();
                char c = next();
                if (c == ']') {
                    return out;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected ',' or ']' at offset " + (pos - 1));
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                char escape = next();
                switch (escape) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (pos + 4 > input.length()) {
                            throw new IllegalArgumentException("truncated \\u escape");
                        }
                        out.append((char) Integer.parseInt(input.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> throw new IllegalArgumentException("bad escape \\" + escape);
                }
            }
        }

        private Object number() {
            int start = pos;
            if (peek() == '-' || peek() == '+') {
                pos++;
            }
            boolean fractional = false;
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    fractional = fractional || c == '.' || c == 'e' || c == 'E';
                    pos++;
                } else {
                    break;
                }
            }
            String text = input.substring(start, pos);
            if (text.isEmpty()) {
                throw new IllegalArgumentException("expected a value at offset " + start);
            }
            // Integers stay integers: a row limit of 10000 must not come back
            // as 10000.0 and then fail to be used as a count.
            if (!fractional) {
                try {
                    return Long.parseLong(text);
                } catch (NumberFormatException ignored) {
                    // Falls through to double for values beyond long range.
                }
            }
            return Double.parseDouble(text);
        }

        private char peek() {
            return pos < input.length() ? input.charAt(pos) : '\0';
        }

        private char next() {
            if (done()) {
                throw new IllegalArgumentException("unexpected end of input");
            }
            return input.charAt(pos++);
        }

        private void expect(char expected) {
            char c = next();
            if (c != expected) {
                throw new IllegalArgumentException("expected '" + expected + "' at offset " + (pos - 1));
            }
        }
    }

    // --- typed accessors, so callers do not cast everywhere ---

    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object value) {
        if (value instanceof Map) {
            return (Map<String, Object>) value;
        }
        return new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Object> asArray(Object value) {
        if (value instanceof List) {
            return (List<Object>) value;
        }
        return new ArrayList<>();
    }

    static String string(Map<String, Object> object, String key) {
        Object value = object.get(key);
        return value instanceof String ? (String) value : null;
    }

    static long number(Map<String, Object> object, String key, long fallback) {
        Object value = object.get(key);
        return value instanceof Number ? ((Number) value).longValue() : fallback;
    }

    static boolean bool(Map<String, Object> object, String key, boolean fallback) {
        Object value = object.get(key);
        return value instanceof Boolean ? (Boolean) value : fallback;
    }
}
