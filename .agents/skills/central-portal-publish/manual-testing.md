# Manual testing a deployment bundle

Test a **validated** bundle as a dependency before publishing it. The Portal exposes two download roots:

- `https://central.sonatype.com/api/v1/publisher/deployment/<deploymentId>/download/<relativePath>` — files from one specific deployment
- `https://central.sonatype.com/api/v1/publisher/deployments/download/<relativePath>` — the most recent validated deployment containing that file

Both serve the same artifact content; the first is pinned to a deployment, the second floats to any validated one. Use the floating root when the deployment ID itself is the thing you are testing around.

## Maven

Add to `~/.m2/settings.xml` (or your CI settings):

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <id>central.manual.testing</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Authorization</name>
            <value>Bearer ${env.TOKEN}</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>central.manual.testing</id>
      <repositories>
        <repository>
          <id>central.manual.testing</id>
          <name>Central Testing repository</name>
          <url>https://central.sonatype.com/api/v1/publisher/deployments/download</url>
        </repository>
      </repositories>
    </profile>
  </profiles>
</settings>
```

Resolve through it with `mvn <command> -Pcentral.manual.testing`.

## Gradle

`build.gradle`:

```groovy
repositories {
    maven {
        name = "centralManualTesting"
        url = "https://central.sonatype.com/api/v1/publisher/deployments/download/"
        credentials(HttpHeaderCredentials)
        authentication {
            header(HttpHeaderAuthentication)
        }
    }
    mavenCentral()
}
```

`gradle.properties`:

```properties
centralManualTestingAuthHeaderName=Authorization
centralManualTestingAuthHeaderValue=Bearer ${env.TOKEN}
```

**Done when** the dependency resolves from a URL beginning `https://central.sonatype.com/api/v1/publisher/deployments/download` rather than from Maven Central.
