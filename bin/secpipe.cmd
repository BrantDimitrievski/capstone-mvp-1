@echo off
setlocal
set "BIN_DIR=%~dp0"
set "HOME_DIR=%BIN_DIR%.."

set "JAR="
if exist "%HOME_DIR%\lib\secpipe.jar" set "JAR=%HOME_DIR%\lib\secpipe.jar"
if not defined JAR if exist "%HOME_DIR%\target\secpipe.jar" set "JAR=%HOME_DIR%\target\secpipe.jar"
if not defined JAR (
  echo error: secpipe.jar not found. 1>&2
  echo hint:  build it first with: mvnw.cmd -q package -DskipTests 1>&2
  exit /b 2
)

set "JAVA=java"
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA=%JAVA_HOME%\bin\java.exe"
where "%JAVA%" >nul 2>nul
if errorlevel 1 if not exist "%JAVA%" (
  echo error: no Java runtime found ^(JAVA_HOME is unset and 'java' is not on PATH^). 1>&2
  echo hint:  install JDK 21+ ^(e.g. https://adoptium.net^) and make sure 'java -version' works. 1>&2
  exit /b 2
)

if not defined SECPIPE_JAVA_OPTS set "SECPIPE_JAVA_OPTS=-Xss8m"
"%JAVA%" %SECPIPE_JAVA_OPTS% -jar "%JAR%" %*
exit /b %ERRORLEVEL%
