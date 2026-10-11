# PhoneShield (starter build)

PhoneShield is an Android security-checkup prototype assembled from the supplied Kotlin source files. It includes a device checkup, sensitive-permission audit, offline link heuristics, password-breach range lookup, Wi-Fi information panel, and an experimental local DNS VPN filter.

## Build from an Android phone using GitHub Actions

1. Create a GitHub account if you do not already have one.
2. Create a **public or private repository** named `PhoneShield` on GitHub.
3. Upload the contents of this folder to the repository (the `.github/workflows/android.yml` file must be included). On GitHub's website, you can use **Add file → Upload files**; for a folder with many files, a ZIP upload is not expanded automatically, so extract it first or use GitHub's mobile-friendly web editor / a Git client app.
4. Open the repository's **Actions** tab and select **Build PhoneShield APK**.
5. Tap **Run workflow**. Wait for the workflow to finish successfully.
6. Open the completed run and download the `PhoneShield-debug-apk` artifact. Extract the artifact ZIP to get `app-debug.apk`.
7. Open the APK on your Android phone and allow installation from that source if Android asks. Only install builds you created from source you trust.

Pushing a commit to the `main` branch also triggers a build.

## Local build

Requires JDK 17, Android SDK platform 35, and Gradle 8.7:

```bash
gradle :app:assembleDebug
```

## Current limitations / safety notes

- This is an early prototype, not a professionally audited security product. Do not treat the security score or link scanner as a guarantee that a device or URL is safe.
- The Wi-Fi panel intentionally does not claim to identify the current access point's encryption reliably; Android restricts this information on newer versions.
- The DNS firewall is experimental and only handles a narrow subset of IPv4 UDP DNS packets. IPv6, TCP DNS, fragmentation, and other edge cases are not fully supported. Test carefully; do not depend on it as your only protection.
- The starter domain blocklist is small. A larger maintained list and safe update mechanism are not included yet.
- The password checker sends only the first five hexadecimal characters of a SHA-1 hash to the Have I Been Pwned range API, not the password itself. Do not use the app with passwords you cannot safely submit to that service's range-check protocol.
- `QUERY_ALL_PACKAGES` is a sensitive Android permission and may require special policy declarations if distributed through Google Play.
- This project targets Android API 33 for its initial prototype. Review platform requirements and security behavior before publishing.

## Privacy design in the supplied source

The app does not implement accounts, analytics, or a remote backend. The breach checker contacts `api.pwnedpasswords.com`; the DNS service contacts Quad9 over HTTPS. Android system services are queried locally for the device checkup and app-permission audit.

## v0.2: Assistant and auto-manager

- **Offline assistant:** a keyword-rule chat that explains your score, what to fix first, risky apps and more. No AI model, no network.
- **Auto-manager:** a WorkManager job rescans about every 12 hours and notifies only about NEW failing checks or NEW apps with sensitive access. The first scan only sets a baseline.
