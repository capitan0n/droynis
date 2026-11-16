package io.github.capitan0n.droynis.checks.base

/**
 * The signing keys of the app stores Droynis knows.
 *
 * Android records which app installed each app by package name only, and an app can take an app
 * store's package name on any phone where that store isn't installed. A fake "F-Droid" would make
 * every app it installs count as coming from an app store. So a store installed as a user app
 * counts only when it is signed with one of its published keys, or was itself installed by a
 * genuine app store. A store that came with the phone counts as it is: a user app can't replace a
 * system app without that app's key.
 *
 * Keys are SHA-256 fingerprints of signing certificates, written as each source publishes them.
 */
object StoreKeys {

    /** One app store and the keys its builds are signed with. */
    class Store(
        val packageName: String,
        val name: String,
        sha256: List<String>,
        /**
         * Every build of the store is signed with one of [keys]. False when some builds use keys
         * Droynis doesn't know, such as F-Droid's own build of a store, signed with a key F-Droid
         * keeps for that app: a copy with another key then isn't an impostor, only unverified.
         */
        val allKeysKnown: Boolean,
        /** Where the keys come from, for the reader. */
        @Suppress("unused") val source: String,
    ) {
        val keys: Set<String> = sha256.mapTo(sortedSetOf(), ::normalize)
    }

    /** What Droynis can say about a user-installed or system copy of an app store. */
    enum class Verdict(val counts: Boolean) {
        /** Part of the phone's firmware. */
        PREINSTALLED(counts = true),

        /** Signed with one of the store's published keys. */
        KEY_MATCHES(counts = true),

        /** Installed by another app store that is genuine itself, which checked it before installing. */
        INSTALLED_BY_STORE(counts = true),

        /** Signed with a key Droynis doesn't know for this store, which also ships builds with other keys. */
        UNVERIFIED(counts = true),

        /** Its signing key couldn't be read. */
        KEY_UNREAD(counts = true),

        /** Not signed with any of the store's keys, though Droynis knows all of them: it only uses the store's name. */
        WRONG_KEY(counts = false),
    }

    private val GOOGLE = listOf(
        // GrapheneOS validates its sandboxed Google Play against these three ("bd32", "38d1", "58e1").
        "7ce83c1b71f3d572fed04c8d40c5cb10ff75e6d87d9df6fbd53f0468c2905053",
        "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
        "1975b2f17177bc89a5dff31f9e64a6cae281a53dc1d1d59b1d147fe1c82afa00",
    )
    private const val GRAPHENEOS = "GrapheneOS platform_frameworks_base, services/core/java/com/android/server/pm/ext/" +
        "PackageExtInit.java, mainGmsCerts() (865521d4)"

    private const val RUAM_MIJ = "Ruam Mij (github.com/akexorcist/ruam-mij-android, Apache-2.0), " +
        "base/data/.../Installers.kt (807cfce)"
    private const val SAMSUNG_STORE = "FB:A3:AF:4E:77:57:D9:01:6E:95:3F:B3:EE:46:71:CA:2B:D9:AF:72:5F:9A:53:D5:2E:D4:A3:8E:AA:A0:89:01"
    private const val SAMSUNG = "34:DF:0E:7A:9F:1C:F1:89:2E:45:C0:56:B4:97:3C:D8:1C:CF:14:8A:40:50:D1:1A:EA:4A:C5:A6:5F:90:0A:42"
    private const val XIAOMI = "C9:00:9D:01:EB:F9:F5:D0:30:2B:C7:1B:2F:E9:AA:9A:47:A4:32:BB:A1:73:08:A3:11:1B:75:D7:B2:14:90:25"
    private const val VIVO = "BC:C3:5D:4D:36:06:F1:54:F0:40:2A:B7:63:4E:84:90:C0:B2:44:C2:67:5C:3C:62:38:98:69:87:02:4F:0C:02"

    val STORES: Map<String, Store> = listOf(
        Store("com.android.vending", "Google Play", GOOGLE, allKeysKnown = true, GRAPHENEOS),
        Store(
            "org.fdroid.fdroid", "F-Droid",
            listOf("43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab"),
            allKeysKnown = true,
            "f-droid.org/docs/Release_Channels_and_Signing_Keys (fdroid-website a168b6f; matches the certificate published there)",
        ),
        // Built and signed by F-Droid with a key of its own; installed by F-Droid, it counts as genuine.
        Store("org.fdroid.basic", "F-Droid Basic", emptyList(), allKeysKnown = false, "none published"),
        Store("com.machiav3lli.fdroid", "Neo Store", emptyList(), allKeysKnown = false, "none published"),
        Store(
            "com.looker.droidify", "Droid-ify",
            listOf("ED:88:59:C5:5A:F3:11:16:26:58:B9:4A:F9:82:B9:F0:91:DC:D2:76:28:D4:DE:34:86:D1:21:7E:BF:3C:99:35"),
            allKeysKnown = false, // "Signature for versions from F-Droid might be different"
            "github.com/Droid-ify/client README (ff1453e)",
        ),
        Store(
            "app.accrescent.client", "Accrescent",
            listOf("067a40c4193aad51ac87f9ddfdebb15e24a1850babfa4821c28c5c25c3fdc071"),
            allKeysKnown = true,
            "github.com/accrescent/accrescent README (6a0b9ef)",
        ),
        Store(
            "com.aurora.store", "Aurora Store",
            listOf("4C:62:61:57:AD:02:BD:A3:40:1A:72:63:55:5F:68:A7:96:63:FC:3E:13:A4:D4:36:9A:12:57:09:41:AA:28:0F"),
            allKeysKnown = false, // F-Droid signs its own build with its own key
            "gitlab.com/AuroraOSS/AuroraStore README (12840634)",
        ),
        Store(
            "dev.imranr.obtainium", "Obtainium",
            listOf("B3:53:60:1F:6A:1D:5F:D6:60:3A:E2:F5:0B:E8:0C:F3:01:36:7B:86:B6:AB:8B:1F:66:24:3D:A9:6C:D5:73:62"),
            allKeysKnown = true, // F-Droid's build is reproducible, but is a separate package (dev.imranr.obtainium.fdroid)
            "github.com/ImranR98/Obtainium README (35c3e7f)",
        ),
        Store("com.sec.android.app.samsungapps", "Galaxy Store", listOf(SAMSUNG_STORE), allKeysKnown = true, RUAM_MIJ),
        Store(
            "com.huawei.appmarket", "AppGallery",
            listOf("3B:AF:59:A2:E5:33:1C:30:67:5F:AB:35:FF:5F:FF:0D:11:61:42:D3:D4:66:4F:1C:3C:B8:04:06:8B:40:61:4F"),
            allKeysKnown = true, RUAM_MIJ,
        ),
        Store(
            "com.amazon.venezia", "Amazon Appstore",
            listOf("2F:19:AD:EB:28:4E:B3:6F:7F:07:78:61:52:B9:A1:D1:4B:21:65:32:03:AD:0B:04:EB:BF:9C:73:AB:6D:76:25"),
            allKeysKnown = true, RUAM_MIJ,
        ),
        Store("com.xiaomi.mipicks", "Xiaomi GetApps", listOf(XIAOMI), allKeysKnown = true, RUAM_MIJ),
        Store("com.xiaomi.market", "Xiaomi App Store", listOf(XIAOMI), allKeysKnown = true, RUAM_MIJ),
        Store(
            "com.heytap.market", "OPPO App Market",
            listOf("28:9C:C3:42:9F:49:64:60:B6:6A:C2:A8:76:C0:40:09:1A:AE:F5:5B:5E:B9:42:C2:CE:69:7E:F3:B1:20:14:59"),
            allKeysKnown = true, RUAM_MIJ,
        ),
        Store("com.vivo.appstore", "vivo App Store", listOf(VIVO), allKeysKnown = true, RUAM_MIJ),
        Store("com.bbk.appstore", "vivo App Store", listOf(VIVO), allKeysKnown = true, RUAM_MIJ),
        // Comes with /e/OS; its APK is also offered for other systems.
        Store("foundation.e.apps", "App Lounge", emptyList(), allKeysKnown = false, "none published"),
        Store("com.samsung.android.app.watchmanager", "Galaxy Wearable", listOf(SAMSUNG), allKeysKnown = true, RUAM_MIJ),
    ).associateBy { it.packageName }

    /** Packages whose signing keys the app list reads ([InstalledApp.signerSha256]). */
    val PACKAGES: Set<String> get() = STORES.keys

    /**
     * What Droynis can say about [store], an installed app that uses an app store's package name.
     * Null when [store] isn't a known store. [inventory] finds the app that installed it.
     */
    fun verify(store: InstalledApp, inventory: Map<String, InstalledApp>): Verdict? = verify(store, inventory, depth = 0)

    /**
     * True when the app called [installer] uses an app store's name without any of its keys: the apps
     * it installed did not come from that store. False when it isn't installed (Android forgets an
     * installer when it is uninstalled) or isn't a known store.
     */
    fun isImpostor(installer: String?, inventory: Map<String, InstalledApp>?): Boolean {
        val app = inventory?.get(installer ?: return false) ?: return false
        return verify(app, inventory) == Verdict.WRONG_KEY
    }

    private fun verify(store: InstalledApp, inventory: Map<String, InstalledApp>, depth: Int): Verdict? {
        val known = STORES[store.packageName] ?: return null
        val signers = store.signerSha256
        return when {
            store.isSystem -> Verdict.PREINSTALLED
            signers != null && signers.any { it in known.keys } -> Verdict.KEY_MATCHES
            installedByGenuineStore(store, inventory, depth) -> Verdict.INSTALLED_BY_STORE
            signers.isNullOrEmpty() -> Verdict.KEY_UNREAD
            known.allKeysKnown -> Verdict.WRONG_KEY
            else -> Verdict.UNVERIFIED
        }
    }

    /** Another app store installed [store], and it is genuine itself; a chain of stores ends after a few. */
    private fun installedByGenuineStore(store: InstalledApp, inventory: Map<String, InstalledApp>, depth: Int): Boolean {
        val installer = inventory[store.installer ?: return false] ?: return false
        if (installer.packageName == store.packageName || depth >= MAX_CHAIN) return false
        val verdict = verify(installer, inventory, depth + 1) ?: return false
        return verdict == Verdict.PREINSTALLED || verdict == Verdict.KEY_MATCHES || verdict == Verdict.INSTALLED_BY_STORE
    }

    private const val MAX_CHAIN = 3

    /** "AB:CD:…" or "abcd…" to "abcd…". */
    fun normalize(fingerprint: String): String = fingerprint.replace(":", "").lowercase()
}
