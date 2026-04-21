# SMS Budget Tracker 💰

A personal finance app that reads your bank SMS messages and automatically sorts them into spending categories — no login, no bank integration, no cloud. Everything runs on your Android device.

> Built as a personal project to actually understand where my money goes each month.

---

## What it does

- **Reads bank SMS** — HDFC, SBI, Scapia, ICICI, Axis and more
- **Auto-sorts** into QuickCart, Investments, Insurance, Family, and Miscellaneous
- **Breaks down QuickCart** — Food (Zomato/Swiggy) vs Grocery (Blinkit/BigBasket/Zepto)
- **Detects SIPs** — Groww, Zerodha, Kuvera show up as Investments automatically
- **Tags transactions** — tag once, all same-brand transactions fill automatically
- **Fixed expense tracking** — declare your SIP, insurance, parents transfer once; app cross-checks SMS amounts
- **100% on-device** — no server, no account, no data leaves your phone

---

## Install on Android

### Option 1 — Download from GitHub Releases (easiest)

1. Go to the [**Releases**](../../releases/latest) page of this repo
2. Download the latest `.apk` file to your phone
3. Settings → Security → **Enable "Install from unknown sources"**
4. Open the downloaded APK → tap **Install**

The app will ask for SMS permission on first launch — that's the only permission it needs.

### Option 2 — Build it yourself

**Prerequisites:** Node 20, Java 17, Android Studio (or Android SDK)

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/budget-tracker-app.git
cd budget-tracker-app

# Install dependencies
npm install

# Build the web app
npm run build

# Sync to Android
npx cap sync android
```

Then either:
- Open the `android/` folder in **Android Studio** → Build → Build APK(s)
- Or via command line: `cd android && ./gradlew assembleDebug`

APK lands at `android/app/build/outputs/apk/debug/app-debug.apk`

---

## Set up automatic APK builds (GitHub Actions)

Every push to `main` automatically builds a new APK and publishes it to the Releases page — no local setup needed after the first time.

### Why updates might say "App not installed"

Android requires every APK update to be signed with the **same key** as the installed version. The default debug build uses a randomly-generated key each time, so Android rejects the update.

**Fix: set up a consistent signing key (one-time, ~5 minutes)**

**1 — Generate a keystore on your computer**
```bash
keytool -genkeypair -v \
  -keystore budgettracker.jks \
  -alias budgettracker \
  -keyalg RSA -keysize 2048 -validity 36500 \
  -storepass YOUR_STORE_PASSWORD \
  -keypass YOUR_KEY_PASSWORD \
  -dname "CN=Budget Tracker, OU=App, O=Personal, L=IN, S=IN, C=IN"
```
> `keytool` comes with Java. If you have Android Studio installed, Java is already there.

**2 — Convert to base64**
```bash
# macOS / Linux
base64 -w 0 budgettracker.jks > keystore.b64

# Windows (PowerShell)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("budgettracker.jks")) | Out-File keystore.b64
```

**3 — Add 4 secrets to your GitHub repo**

Settings → Secrets and variables → Actions → New repository secret

| Secret name    | Value                               |
|----------------|-------------------------------------|
| `KEYSTORE_B64` | Paste the full contents of `keystore.b64` |
| `KEYSTORE_PASS`| The password you used as `YOUR_STORE_PASSWORD` |
| `KEY_ALIAS`    | `budgettracker`                     |
| `KEY_PASS`     | The password you used as `YOUR_KEY_PASSWORD` |

**4 — Push anything to main**

GitHub Actions will now build a release-signed APK, auto-increment the version number, and publish it to Releases. Tap the APK on your phone → Android shows "Update app" → done.

---

## Privacy

The app reads only two things from each SMS:
- The ₹ amount
- The brand/merchant name (checked against a predefined allowlist)

It never reads or stores OTPs, PINs, account numbers, card numbers, or any personal message text. No data is uploaded anywhere — the only outbound request is loading the Inter Tight font from Google Fonts CDN.

---

## Tech stack

| Layer | What |
|-------|------|
| UI | React + Vite |
| Native wrapper | Capacitor 8.x |
| SMS reader | Custom Java `SmsPlugin.java` |
| Styling | Inline React styles — Inter Tight, warm cream palette |
| CI/CD | GitHub Actions → signed APK → GitHub Releases |

---

## Project structure

```
budget-tracker-app/
├── src/
│   └── App.jsx                  ← Full app: SMS parsing, UI, categories, tags
├── android/
│   └── app/src/main/java/com/budgettracker/sms/
│       └── SmsPlugin.java       ← Native Android SMS plugin
├── .github/workflows/
│   └── build-apk.yml            ← CI: build + publish APK on every push
└── BUILD_APK.md                 ← Detailed build & signing guide
```

---

## Made by

**Nmay** · [nishimayekar.design@gmail.com](mailto:nishimayekar.design@gmail.com)

Built with Claude · Personal project · Not affiliated with any bank or payment service
