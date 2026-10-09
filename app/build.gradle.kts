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

android {
    namespace = "io.github.capitan0n.droynis"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.capitan0n.droynis"
        minSdk = 26
        targetSdk = 37
        versionCode = 18
        versionName = "0.12.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
