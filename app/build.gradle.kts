import java.util.Locale
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Optional release signing: keystore.properties for local builds, DROYNIS_* environment variables
// for the release workflow. Neither is in git; F-Droid ignores both and signs its own build.
val keystoreProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.isFile) file.inputStream().use { load(it) }
}

fun signingValue(key: String, env: String): String? =
    keystoreProperties.getProperty(key) ?: providers.environmentVariable(env).orNull?.takeIf { it.isNotEmpty() }

val releaseKeystore = signingValue("storeFile", "DROYNIS_KEYSTORE")

/** The F-Droid changelog of [versionCode], trimmed; empty when there is none. */
fun changelog(versionCode: Int): String =
    providers.fileContents(
        rootProject.layout.projectDirectory.file("fastlane/metadata/android/en-US/changelogs/$versionCode.txt"),
    ).asText.orNull.orEmpty().trim()

/**
 * [text] as a Java string literal for BuildConfig. Non-ASCII as \u escapes; control characters other
 * than newlines and tabs are dropped, since a \u escape of one would end the literal.
 */
fun javaString(text: String): String = buildString {
    append('"')
    for (c in text) {
        when {
            c == '\\' -> append("\\\\")
            c == '"' -> append("\\\"")
            c == '\n' -> append("\\n")
            c == '\t' -> append("\\t")
            c < ' ' -> Unit
            c.code > 0x7e -> append("\\u%04x".format(Locale.ROOT, c.code))
            else -> append(c)
        }
    }
    append('"')
}

android {
    androidResources {
        generateLocaleConfig = true
    }

    namespace = "io.github.capitan0n.droynis"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.capitan0n.droynis"
        minSdk = 26
        targetSdk = 37
        // Written out: the release workflow and F-Droid read both from this file.
        versionCode = 23
        versionName = "0.17.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // This version's changelog, which the app shows once after an update ("What's new").
        buildConfigField("String", "WHATS_NEW", javaString(changelog(versionCode ?: 0)))
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = rootProject.file(releaseKeystore)
                storePassword = signingValue("storePassword", "DROYNIS_KEYSTORE_PASSWORD")
                keyAlias = signingValue("keyAlias", "DROYNIS_KEY_ALIAS")
                keyPassword = signingValue("keyPassword", "DROYNIS_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Reproducible builds: no git metadata in the APK.
            vcsInfo {
                include = false
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    // F-Droid: drop the dependency metadata block that AGP encrypts for Google Play.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        checkDependencies = true
        warning += "MissingTranslation"
    }
}

dependencies {
    implementation(project(":platform-android"))
    implementation(project(":report"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit4)

    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
