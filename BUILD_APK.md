# Build APK — 3 Options (pick the easiest)

## ✅ Option 1 — Android Studio (Recommended, FREE)
1. Download Android Studio: https://developer.android.com/studio
2. Open Android Studio → File → Open → select the `android/` folder inside this project
3. Wait for Gradle sync to finish (first time takes ~5 min, downloads SDK automatically)
4. Build → Build Bundle(s) / APK(s) → Build APK(s)
5. APK is at: android/app/build/outputs/apk/debug/app-debug.apk
6. Transfer to phone via USB or Google Drive

## ✅ Option 2 — EAS Build (Cloud, no setup needed)
1. Install: `npm install -g eas-cli`
2. Create free account at expo.dev
3. Login: `eas login`
4. Run from project root: `eas build --platform android --profile preview`
5. Download APK from the link it gives you (builds in ~5 min in the cloud)

## ✅ Option 3 — Command Line (if Android SDK already installed)
```bash
cd android
./gradlew assembleDebug
```
APK output: android/app/build/outputs/apk/debug/app-debug.apk

## Install APK on phone
- Enable "Install from unknown sources" in Android Settings → Security
- Transfer APK file to phone → tap to install
- OR: `adb install app-debug.apk` (USB debugging)
