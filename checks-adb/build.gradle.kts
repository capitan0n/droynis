import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.android.lint)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    api(project(":checks-base"))

    testImplementation(project(":report"))
    // CatalogDocTest documents every tier, so it sees the tiers above this one too.
    testImplementation(project(":checks-shizuku"))
    testImplementation(kotlin("test"))
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    // CatalogDocTest compares docs/CHECKS.md with the check specs, and rewrites it with UPDATE_CHECKS_DOC=1.
    val checksDoc = rootProject.layout.projectDirectory.file("docs/CHECKS.md")
    inputs.files(checksDoc).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("updateChecksDoc", providers.environmentVariable("UPDATE_CHECKS_DOC").orElse(""))
    systemProperty("droynis.checksDoc", checksDoc.asFile.path)
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
