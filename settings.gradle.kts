pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "droynis"

// Directories group the modules by layer; project paths stay flat (":checks-adb"), so Gradle
// commands, dependencies and Kotlin module names don't depend on where a module lives.
fun module(path: String, directory: String) {
    include(path)
    project(path).projectDir = file(directory)
}

// Pure Kotlin/JVM: no Android SDK needed, unit-testable on any JVM.
module(":core-model", "core/model")
module(":report", "core/report")
module(":checks-base", "checks/base")
module(":checks-adb", "checks/adb")
module(":checks-shizuku", "checks/shizuku")
module(":checks-root", "checks/root")

// Android: the only modules that touch framework APIs.
module(":platform-android", "platform/android")
include(":app")
