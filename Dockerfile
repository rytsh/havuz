# syntax=docker/dockerfile:1.9
#
# Two images out of one file:
#
#   docker build --target runtime -t havuz .       the pooler
#   docker build --target jdbc    -t havuz:jdbc .  the pooler plus the JDBC bridge
#
# The split is deliberate. Only the JDBC bridge needs a Java runtime, and the
# JVM is larger than everything else here put together; a deployment that talks
# to PostgreSQL has no reason to carry one. Both images come from the same
# `builder` stage, so the binary in them is byte-identical.

# ---------------------------------------------------------------- dashboard --
FROM node:22-bookworm-slim AS ui
ARG PNPM_VERSION=11.1.1
RUN npm install --global "pnpm@${PNPM_VERSION}"
WORKDIR /src/ui

# Dependencies first: they change far less often than the Svelte sources, and a
# cached install is the difference between a 10 second and a 90 second build.
COPY ui/package.json ui/pnpm-lock.yaml ui/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# `publicDir` in vite.config.ts points at ../assets, so the icons live outside
# the ui directory and still have to be here.
COPY assets/ /src/assets/
COPY ui/ ./
RUN pnpm run build

# -------------------------------------------------------------------- havuz --
FROM rust:1.86-bookworm AS builder
WORKDIR /src
COPY . .
COPY --from=ui /src/ui/dist ui/dist

# The cache mounts make a rebuild cheap; the copy out of them is required,
# because a cache mount is not part of the resulting layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --package havuz-server --features embed-ui \
    && cp target/release/havuz /usr/local/bin/havuz \
    && /usr/local/bin/havuz --version

# -------------------------------------------------------------- jdbc agent --
FROM eclipse-temurin:21-jdk AS agent
WORKDIR /agent
COPY agent/ ./
# HAVUZ_JAVAC=1 keeps build.sh from starting a container of its own; we are
# already standing in a JDK.
RUN HAVUZ_JAVAC=1 bash build.sh

# ------------------------------------------------------------- jdbc drivers --
FROM debian:13-slim AS drivers
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG MAVEN_REPO=https://repo1.maven.org/maven2

# name=groupId:artifactId:version, whitespace separated. Only drivers that may
# actually be redistributed are here. Oracle, DB2, Informix and Teradata are
# not, so they are mounted or added with --build-arg by whoever accepted their
# licence; see the Docker section of the README.
#
# The file each one lands in is named without a version on purpose: a pool's
# driver_paths setting then survives an image upgrade.
ARG DRIVERS="\
postgresql=org.postgresql:postgresql:42.7.13 \
mariadb=org.mariadb.jdbc:mariadb-java-client:3.5.10 \
mysql=com.mysql:mysql-connector-j:9.5.0 \
sqlserver=com.microsoft.sqlserver:mssql-jdbc:13.4.0.jre11 \
ingres=com.ingres.jdbc:iijdbc:12.1-4.6.5 \
h2=com.h2database:h2:2.4.240"

RUN set -eu; \
    mkdir -p /opt/havuz/drivers; \
    : > /opt/havuz/drivers/MANIFEST.txt; \
    for entry in ${DRIVERS}; do \
        name="${entry%%=*}"; \
        coordinate="${entry#*=}"; \
        group="$(printf '%s' "${coordinate%%:*}" | tr . /)"; \
        rest="${coordinate#*:}"; \
        artifact="${rest%%:*}"; \
        version="${rest##*:}"; \
        url="${MAVEN_REPO}/${group}/${artifact}/${version}/${artifact}-${version}.jar"; \
        curl --fail --silent --show-error --location --retry 3 \
             --output "/opt/havuz/drivers/${name}.jar" "${url}"; \
        printf '%s\t%s\n' "${name}.jar" "${coordinate}" >> /opt/havuz/drivers/MANIFEST.txt; \
    done; \
    cat /opt/havuz/drivers/MANIFEST.txt

# ----------------------------------------------------------------- runtime --
FROM debian:13-slim AS runtime
LABEL org.opencontainers.image.title="havuz" \
      org.opencontainers.image.description="PostgreSQL connection pooler with a dashboard" \
      org.opencontainers.image.source="https://github.com/rytsh/havuz" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 havuz \
    && useradd --system --uid 10001 --gid havuz --home-dir /var/lib/havuz havuz \
    && mkdir -p /var/lib/havuz /etc/havuz \
    && chown havuz:havuz /var/lib/havuz

COPY --from=builder /usr/local/bin/havuz /usr/local/bin/havuz
COPY docker/entrypoint.sh /usr/local/bin/havuz-entrypoint
COPY docker/havuz.toml /etc/havuz/havuz.toml
COPY havuz.example.toml /etc/havuz/havuz.example.toml

USER havuz
WORKDIR /var/lib/havuz
VOLUME ["/var/lib/havuz"]

# The dashboard and the admin API. Pool ports are declared per pool and cannot
# be known here, so publish those yourself: -p 6432:6432.
EXPOSE 7432

ENTRYPOINT ["havuz-entrypoint"]
CMD ["run", "--config", "/etc/havuz/havuz.toml"]

# -------------------------------------------------------------------- jdbc --
# Everything above plus a JVM, the agent JAR and the drivers that may be
# shipped. `havuz` looks for the JAR in /usr/share/havuz by itself, so a pool
# only has to name its driver.
FROM eclipse-temurin:21-jre-noble AS jdbc
LABEL org.opencontainers.image.title="havuz (JDBC)" \
      org.opencontainers.image.description="havuz with the JDBC bridge: a JRE, the agent and redistributable drivers" \
      org.opencontainers.image.source="https://github.com/rytsh/havuz" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 havuz \
    && useradd --system --uid 10001 --gid havuz --home-dir /var/lib/havuz havuz \
    && mkdir -p /var/lib/havuz /etc/havuz /opt/havuz/drivers \
    && chown havuz:havuz /var/lib/havuz

COPY --from=builder /usr/local/bin/havuz /usr/local/bin/havuz
COPY --from=agent /agent/build/havuz-agent.jar /usr/share/havuz/havuz-agent.jar
COPY --from=drivers /opt/havuz/drivers/ /opt/havuz/drivers/
COPY docker/entrypoint.sh /usr/local/bin/havuz-entrypoint
COPY docker/havuz.toml /etc/havuz/havuz.toml
COPY havuz.example.toml /etc/havuz/havuz.example.toml

USER havuz
WORKDIR /var/lib/havuz
VOLUME ["/var/lib/havuz"]
EXPOSE 7432

ENTRYPOINT ["havuz-entrypoint"]
CMD ["run", "--config", "/etc/havuz/havuz.toml"]
