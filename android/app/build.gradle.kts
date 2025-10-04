plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.pqrypt.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.pqrypt.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        // Enable 16KiB page size support
        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
                )
                cFlags += "-Wl,-z,max-page-size=16384"
                cppFlags += "-Wl,-z,max-page-size=16384"
            }
        }
    }
    
    lint {
        baseline = file("lint-baseline.xml")
        abortOnError = false
        ignoreWarnings = true
        checkReleaseBuilds = false
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Native build flags for maximum performance
            externalNativeBuild {
                cmake {
                    arguments("-DCMAKE_BUILD_TYPE=Release")
                    cppFlags("-O3 -flto=full -DNDEBUG -Wl,-z,max-page-size=16384")
                }
            }
        }
        debug {
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Enable code optimization for debug builds
            isDebuggable = true
            isJniDebuggable = true
            // Enable native debug symbols
            ndk {
                debugSymbolLevel = "FULL"
            }
            // Enable R8 full mode for better optimization
            isCrunchPngs = true
            // Enable code optimization
            externalNativeBuild {
                cmake {
                    arguments("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
                    cppFlags("-O3 -flto=full -Wl,-z,max-page-size=16384")
                }
            }
        }
    }
    
    // Rename APK output files
    applicationVariants.all {
        outputs.all {
            val output = this as com.android.build.gradle.internal.api.BaseVariantOutputImpl
            val variantName = name
            output.outputFileName = if (variantName.contains("release")) {
                "PQrypt.apk"
            } else {
                "PQrypt-debug.apk"
            }
        }
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        viewBinding = true
    }
    lint {
        disable += "ProtectedPermissions"
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation("androidx.biometric:biometric:1.1.0")
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}