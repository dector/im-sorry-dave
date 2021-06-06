import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.5.10"
}

dependencies {
    implementation(platform("org.http4k:http4k-bom:4.9.5.0"))
    implementation("org.http4k:http4k-core")
    implementation("org.http4k:http4k-server-netty")

    implementation("org.tinylog:tinylog-api-kotlin:2.3.2")
    implementation("org.tinylog:tinylog-impl:2.3.2")

    implementation("org.hjson:hjson:3.0.0")

    implementation("com.auth0:java-jwt:3.16.0")

    implementation("org.jetbrains.kotlinx:kotlinx-html-jvm:0.7.3")
}

group = "space.dector.gatekeeper"
version = "0.1-SNAPSHOT"

repositories {
    mavenCentral()
    maven(url = "https://maven.pkg.jetbrains.space/public/p/kotlinx-html/maven")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
    kotlinOptions.freeCompilerArgs += "-Xopt-in=kotlin.RequiresOptIn"
}

val test by tasks.getting(Test::class) {
    useJUnitPlatform()
}
