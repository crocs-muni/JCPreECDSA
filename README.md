# JCPreECDSA

A JavaCard implementation of two-party ECDSA with trusted precomputation.

## Building the Applet

To build the applet, clone this repository with submodules, set your card type in [the main applet](applet/src/main/java/jcpreecdsa/JCPreECDSA.java#L10) file on [line 10](applet/src/main/java/jcpreecdsa/JCPreECDSA.java#L10), and run:

```
./gradlew buildJavaCard
```

The resulting cap file can be found in `applet/build/javacard/jcpreecdsa.cap`.

## Testing and performance measurement

Tests can be run using the following command. 

```
./gradlew test
```