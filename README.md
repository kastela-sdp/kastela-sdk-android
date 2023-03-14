# KASTELA Server SDK for ANDROID

## Related Link

- [API docs](https://kastela-sdp.github.io/kastela-sdk-android/id/hash/kastela/package-summary.html)
- [Packages](https://github.com/kastela-sdp/kastela-sdk-android/packages/1812112)

## Installation
1. Add to settings.gradle 
```
repositories {
  ...
  maven {
            url = "https://maven.pkg.github.com/kastela-sdp/kastela-sdk-android"
            credentials {
                username = 'yourgithubusername'
                password = 'yourpersonalaccesstoken'
            }
        }
  ...
}
```
2. Add to build.gradle (check the latest version [here](https://github.com/kastela-sdp/kastela-sdk-android/packages/1812112))
```
dependencies {
  ...
  implementation 'id.hash.kastela:kastela-sdk-android:0.2.0'
  ...
}
```
## Usage Example

``` java
  // create new client instance
  Client client = new Client("http://127.0.0.1:3200");

  // send protection data in secure way
  Map<String, Object> sendResult = client.secureProtectionSend(result.get("credential").toString(), data);
  System.out.println(sendResult);
```