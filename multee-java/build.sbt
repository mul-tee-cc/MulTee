isSnapshot := false

ThisBuild / version := "0.7.0" + (if (isSnapshot.value) "-SNAPSHOT" else "")

ThisBuild / scalaVersion := "2.13.8"

Compile / mainClass := Some("cc.multee.impl.Util")

artifactName := { (sv: ScalaVersion, module: ModuleID, artifact: Artifact) =>
  artifact.name + "-" + module.revision + "." + artifact.extension }

javacOptions ++= Seq("-source", "1.8", "-target", "1.8", "-Xlint:deprecation")

ThisBuild / crossPaths := false

ThisBuild / autoScalaLibrary := false

lazy val root = (project in file("."))
  .settings(
    name := "multee-java"
  )

packageBin / packageOptions += Def.task {
  Package.ManifestAttributes(
    java.util.jar.Attributes.Name.CLASS_PATH ->
      ((Runtime/managedClasspath)
        .value
        .files
        .map("lib/"+_.getName)/* :+ "."*/)
        .mkString(" ")
        .replaceAll("scala-([a-z]+).jar", s"scala-$$1-${scalaVersion.value}.jar")
  )
}.value

libraryDependencies += "io.vavr" % "vavr" % "0.10.4"

val myPackage = taskKey[Unit]("Copy jars")
myPackage := {
  val dir = baseDirectory.value / "target" / "lib"
  (Runtime/managedClasspath).value
    .files.foreach{ (f) => IO.copyFile(f, dir / f.getName, preserveLastModified=true) }
}
myPackage := (myPackage dependsOn Compile/packageBin).value

val myIdent = taskKey[Unit]("Add ident")
myIdent := {
  val (_, file) = (Compile / packageBin / packagedArtifact).value
  val path = file.getAbsolutePath
  import scala.sys.process._
  {
    s"unzip -p $path libmultee_jni.so" #| "grep -U -z Revision:.MulTee" #|
      "xargs -0 -n 1" #| "tee ident.rcs"
  } #&& s"zip -0m $path ident.rcs" !
}

publish := (publish dependsOn myPackage dependsOn myIdent).value
Compile / packageDoc / publishArtifact := false
Compile / packageSrc / publishArtifact := false

lazy val ignoreArtifactory = settingKey[Boolean]("Publish locally instead of Artifactory")

ignoreArtifactory := true

credentials += Credentials("Artifactory Realm", "artifactory.multee.cc",  sys.env.getOrElse("ART_USER", "changeit"), sys.env.getOrElse("ART_PASS","gofigure"))

organization := "cc.multee"
moduleName := "multee-java"

publishTo := {
  if (ignoreArtifactory.value)
    Some(Resolver.file("file", new File("../artifactory/java")))
  else
    Some("Artifactory Realm" at (if (isSnapshot.value) "https://artifactory.multee.cc/artifactory/snapshots;build.timestamp=" + new java.util.Date().getTime else "elsewhere"))
}

publishConfiguration := publishConfiguration.value.withOverwrite(true)//.withPublishMavenStyle(true)

