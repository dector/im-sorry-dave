import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.5.10"
}

dependencies {
    implementation(platform("org.http4k:http4k-bom:4.9.5.0"))
    implementation("org.http4k:http4k-core")
    implementation("org.http4k:http4k-server-netty")
}

group = "space.dector.gatekeeper"
version = "0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
    kotlinOptions.freeCompilerArgs += "-Xopt-in=kotlin.RequiresOptIn"
}

val test by tasks.getting(Test::class) {
    useJUnitPlatform()
}
