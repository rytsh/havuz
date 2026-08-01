#!/usr/bin/env bash
#
# Build the JDBC agent.
#
# Runs javac in a container so contributors do not need a JDK installed; only a
# JRE is needed to run the result. Set HAVUZ_JAVAC=1 to use a local JDK instead.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="$HERE/build/havuz-agent.jar"

# Java 17 rather than 21: it is what long-lived enterprise images ship, and this
# agent exists precisely to reach databases that live in such places.
RELEASE=17
IMAGE="${HAVUZ_JDK_IMAGE:-eclipse-temurin:21-jdk}"

BUILD='set -eu
rm -rf build && mkdir -p build/classes
find src -name "*.java" | sort > build/sources.txt
javac --release '"$RELEASE"' -Xlint:all -Werror -d build/classes @build/sources.txt
jar --create --file build/havuz-agent.jar --main-class com.havuz.agent.Agent -C build/classes .'

if [[ "${HAVUZ_JAVAC:-0}" == "1" ]]; then
  ( cd "$HERE" && bash -c "$BUILD" )
else
  docker run --rm -v "$HERE":/agent -w /agent "$IMAGE" bash -c "$BUILD"
fi

echo "built $JAR ($(du -h "$JAR" | cut -f1))"
