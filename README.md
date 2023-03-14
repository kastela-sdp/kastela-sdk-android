# KASTELA Server SDK for ANDROID

## Related Link

- [API docs](https://kastela-sdp.github.io/kastela-sdk-android/id/hash/kastela/package-summary.html)
- [Packages](https://github.com/kastela-sdp/kastela-sdk-android/packages/1809924)
- [Guide to use Personal Access Token](https://github.com/jcansdale-test/maven-consume)

## Installation
1. Add to pom.mls (check the latest version [here](https://github.com/kastela-sdp/kastela-sdk-android/packages/1809462))
```
<dependencies>
  ...
  <dependency>
    <groupId>id.hash.kastela</groupId>
    <artifactId>kastela-sdk-java</artifactId>
    <version>0.4.1</version> 
  </dependency>
  ...
</dependencies>

<repositories>
  ...
  <repository>
    <id>github</id>
    <name>GitHub kastela-sdp Apache Maven Packages</name>
    <url>https://maven.pkg.github.com/kastela-sdp/*</url>
  </repository>
  ...
</repositories>
```
2. Run
```
mvn install
```
## Usage Example

``` java
  // create new client instance
  Client client = new Client("http://127.0.0.1:3200");

  // send protection data in secure way
  Map<String, Object> sendResult = client.secureProtectionSend(result.get("credential").toString(), data);
  System.out.println(sendResult);
```