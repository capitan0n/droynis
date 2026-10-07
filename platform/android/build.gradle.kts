plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.capitan0n.droynis.platform"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Shizuku creates the shell service by reflection; keep it through the app's R8.
        consumerProguardFiles("consumer-rules.pro")
    }

    buildFeatures {
        // IShellService: the binder interface of Droynis' read-only Shizuku shell.
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":checks-base"))
    api(project(":checks-adb"))
    api(project(":checks-shizuku"))
    api(project(":checks-root"))

    implementation(libs.shizuku.api)
    implementation(libs.shizuku.provider)

    testImplementation(libs.junit4)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
