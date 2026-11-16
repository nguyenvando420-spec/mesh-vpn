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
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    val rustlsVerifierRepoPath =
        providers.gradleProperty("rustlsPlatformVerifierRepo").orNull
            ?: providers.environmentVariable("RUSTLS_PLATFORM_VERIFIER_REPO").orNull
            ?: "${settingsDir.absolutePath}/.m2"
    val rustlsVerifierRepoDir = file(rustlsVerifierRepoPath)

    repositories {
        maven {
            name = "rustlsPlatformVerifierLocal"
            url = uri(rustlsVerifierRepoDir)
            content {
                includeGroup("rustls")
            }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "MeshVPN"
include(":app")
