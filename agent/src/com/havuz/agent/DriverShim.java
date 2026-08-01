package com.havuz.agent;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Lets {@link java.sql.DriverManager} use a driver it loaded itself.
 *
 * <p>{@code DriverManager} silently ignores any driver whose class was not
 * loaded by the caller's class loader. Since a user-supplied JAR necessarily
 * comes from a {@link java.net.URLClassLoader} we created, registering the
 * driver directly does nothing at all: {@code getConnection} then fails with
 * "No suitable driver", which is a spectacularly unhelpful way to say "your
 * driver loaded fine and I refused to look at it".
 *
 * <p>Wrapping it in a class this JAR owns satisfies the check. This is the
 * standard workaround and has been for twenty years.
 */
final class DriverShim implements Driver {
    private final Driver delegate;

    DriverShim(Driver delegate) {
        this.delegate = delegate;
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        return delegate.connect(url, info);
    }

    @Override
    public boolean acceptsURL(String url) throws SQLException {
        return delegate.acceptsURL(url);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
        return delegate.getPropertyInfo(url, info);
    }

    @Override
    public int getMajorVersion() {
        return delegate.getMajorVersion();
    }

    @Override
    public int getMinorVersion() {
        return delegate.getMinorVersion();
    }

    @Override
    public boolean jdbcCompliant() {
        return delegate.jdbcCompliant();
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return delegate.getParentLogger();
    }
}
