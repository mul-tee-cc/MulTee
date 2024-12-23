name := "triple-a-service"

version := "0.7.0"

scalaVersion := "2.13.15"

Compile / mainClass  := Some("cc.multee.triplea.App")

artifactName := { (_,_,_) => "triple-a-service.jar" }

ThisBuild / crossPaths  := false

packageBin / packageOptions += Def.task {
  Package.ManifestAttributes(
    java.util.jar.Attributes.Name.CLASS_PATH ->
      ((Runtime / managedClasspath)
        .value
        .files
        .map("lib/"+_.getName)/* :+ "."*/)
        .mkString(" ")
        .replaceAll("scala-([a-z]+).jar", s"scala-$$1-${scalaVersion.value}.jar")
  )
}.value


retrieveManaged := true

val myPackage = taskKey[Unit]("Copy jars")
myPackage := {
  val dir = baseDirectory.value / "target" / "lib"
  (Runtime / managedClasspath).value
    .files.foreach{ (f) => IO.copyFile(f, dir / f.getName, preserveLastModified=true) }
}

myPackage := (myPackage dependsOn (Compile / packageBin)).value

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.70",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.70"
)

// Apache pekko
libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-stream" % "2.8.6",
  "com.typesafe.akka" %% "akka-actor" % "2.8.5",
  "com.typesafe.akka" %% "akka-http"   % "10.2.10",
  "com.typesafe.akka" %% "akka-http-spray-json" % "10.2.10"
)

//libraryDependencies ++= Seq (
// "org.scala-lang" %  "scala-reflect" % scalaVersion.value
//)

val jacksonFasterxmlVersion = "2.12.6"
libraryDependencies ++= Seq(
  "com.fasterxml.jackson.core"       % "jackson-core" % jacksonFasterxmlVersion force(),
  "com.fasterxml.jackson.core"       % "jackson-annotations" % jacksonFasterxmlVersion force(),
  "com.fasterxml.jackson.core"       % "jackson-databind" % jacksonFasterxmlVersion force(),
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-yaml" % jacksonFasterxmlVersion force(),
  "com.fasterxml.jackson.module"    %% "jackson-module-scala" % jacksonFasterxmlVersion force()
)

libraryDependencies += "org.scodec" %% "scodec-core" % "1.11.10"

libraryDependencies += "org.typelevel" %% "cats-core" % "2.3.0"

libraryDependencies += "com.outr" %% "scribe" % "3.15.2"

resolvers := Seq(
  "artifaketory" at s"file://${target.value.getParentFile.getParentFile / "artifactory" / "java"}",
  DefaultMavenRepository
)
fullResolvers := resolvers.value
