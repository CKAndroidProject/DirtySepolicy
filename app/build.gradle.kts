plugins {
    id("com.android.application")
}

android {
    enableKotlin = false
    namespace = "org.lsposed.dirtysepolicy"
    defaultConfig {
        versionCode = 5
        versionName = "2.2"
    }
    buildTypes {
        release {
            vcsInfo.include = false
            signingConfig = signingConfigs["debug"]
            optimization {
                enable = true
                keepRules {
                    ignoreFromAllExternalDependencies = true
                    includeDefault = false
                }
            }
        }
        debug {
            versionNameSuffix = "-debug"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        aidl = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "**"
        }
    }
    lint {
        checkReleaseBuilds = false
    }
    dependenciesInfo {
        includeInApk = false
    }
}
