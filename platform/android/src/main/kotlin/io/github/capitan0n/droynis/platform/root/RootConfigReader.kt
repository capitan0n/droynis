package io.github.capitan0n.droynis.platform.root

import android.annotation.SuppressLint
import android.content.res.AssetManager
import android.database.sqlite.SQLiteDatabase
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Xml
import io.github.capitan0n.droynis.checks.root.LSPosedCheck
import java.io.File
import org.xmlpull.v1.XmlPullParser
import kotlin.system.exitProcess

/** Fixed read-only queries executed in a short-lived root app_process. */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi", "BlockedPrivateApi")
object RootConfigReader {
    private const val MODULES = "/data/adb/modules"
    private const val DATABASE = "/data/adb/lspd/config/modules_config.db"
    private const val MAX_ROWS = 512
    private const val STOCK = "com.topjohnwu.magisk"

    @JvmStatic
    fun main(args: Array<String>) {
        val user = args.getOrNull(1)?.toIntOrNull()
        if (user == null || user < 0) exitProcess(1)
        try {
            when (args.firstOrNull()) {
                "lsposed" -> readLSPosed(user)
                "tapjack" -> {
                    val pkg = args.getOrNull(2) ?: exitProcess(1)
                    require(pkg.contains('.') && LSPosedCheck.PACKAGE.matches(pkg))
                    val version = args.getOrNull(3)?.toLongOrNull() ?: exitProcess(1)
                    val dir = File("/data/user_de/$user/$pkg")
                    val actualVersion = if (pkg == STOCK) version else hiddenVersion(File(dir, "dyn/current.apk"))
                    println(when (actualVersion) {
                        in 25200L..31000L -> tapjacking(dir, pkg)?.toString() ?: "unknown"
                        31100L -> "no-switch"
                        else -> "unknown"
                    })
                }
                else -> exitProcess(1)
            }
        } catch (_: Exception) {
            exitProcess(1)
        } catch (_: LinkageError) {
            exitProcess(1)
        }
        System.out.flush()
        exitProcess(0)
    }

    // Only ENOENT means missing. An unreadable or incompatible layout must never become an empty result.
    private fun exists(path: String): Boolean = try {
        Os.stat(path)
        true
    } catch (e: ErrnoException) {
        if (e.errno != OsConstants.ENOENT) throw e
        false
    }

    private fun readLSPosed(user: Int) {
        val installs = listOf("$MODULES/zygisk_lsposed", "$MODULES/riru_lsposed").filter(::exists)
        if (installs.isEmpty()) {
            println(if (exists(DATABASE)) "unrecognized installation" else "absent")
            return
        }
        val disabled = installs.all { exists("$it/disable") }
        println("policy=" + if (disabled) "disabled" else policyTest())
        val rows = try {
            moduleScopes(user, DATABASE)
        } catch (_: Exception) {
            null
        }
        if (rows == null) println("inventory=unknown") else rows.forEach(::println)
        println("end")
    }

    private fun policyTest(): String = try {
        val api = Class.forName("android.os.SELinux")
        val check = api.getMethod("checkSELinuxAccess", String::class.java, String::class.java,
            String::class.java, String::class.java)
        val enforcing = api.getMethod("isSELinuxEnforced").invoke(null) == true
        // A failed access query is also returned as false. Verify a standard init permission first.
        when {
            !enforcing || check.invoke(null, "u:r:init:s0", "u:r:init:s0", "process", "fork") != true -> "unknown"
            check.invoke(null, "u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans") == true -> "allowed"
            else -> "denied"
        }
    } catch (_: ReflectiveOperationException) {
        "unknown"
    }

    internal fun moduleScopes(user: Int, database: String): List<String>? {
        // A no-op corruption handler prevents Android's default handler deleting another app's database.
        val flags = SQLiteDatabase.OPEN_READONLY or SQLiteDatabase.NO_LOCALIZED_COLLATORS
        return SQLiteDatabase.openDatabase(database, null, flags) { _ -> }.use { db ->
            val schema = db.version
            if (schema !in 1..4) return null
            // Modules are enabled globally. On secondary profiles expose only modules scoped to that profile.
            val sql = """SELECT m.module_pkg_name, s.app_pkg_name FROM modules AS m
                LEFT JOIN scope AS s ON s.mid = m.mid AND s.user_id = ?
                WHERE m.enabled = 1 AND m.module_pkg_name != 'lspd' AND (? = '0' OR s.mid IS NOT NULL)
                ORDER BY m.module_pkg_name, s.app_pkg_name LIMIT ${MAX_ROWS + 1}"""
            db.rawQuery(sql, arrayOf(user.toString(), user.toString())).use { cursor ->
                val rows = mutableListOf<String>()
                while (cursor.moveToNext()) {
                    val module = cursor.getString(0) ?: return null
                    val target = cursor.getString(1)
                    if (rows.size >= MAX_ROWS || !validName(module) || (target != null && !validName(target))) return null
                    // In schema 3, LSPosed migrated the framework target from "android" to "system".
                    val scope = if (schema < 3 && target == "android") "system" else target.orEmpty()
                    rows += "module\t$module\t$scope"
                }
                rows
            }
        }
    }

    private fun validName(name: String) = name.length <= 255 && LSPosedCheck.PACKAGE.matches(name)

    // Magisk 25.2–31.0 reads su_tapjack and defaults it to true.
    private fun tapjacking(dir: File, pkg: String): Boolean? {
        if (!dir.isDirectory || dir.canonicalFile != dir) return null
        val prefs = File(dir, "shared_prefs/${pkg}_preferences.xml")
        val backup = File(prefs.path + ".bak")
        // Android restores the backup first after an interrupted SharedPreferences write.
        val active = if (exists(backup.path)) backup else prefs
        if (!exists(active.path)) return true
        if (!active.isFile || active.canonicalFile != active || active.length() > 1_048_576) return null
        return active.inputStream().buffered().use { stream ->
            val xml = Xml.newPullParser()
            xml.setInput(stream, null)
            if (xml.nextTag() != XmlPullParser.START_TAG || xml.name != "map") return null
            var saved: Boolean? = null
            while (xml.next() != XmlPullParser.END_DOCUMENT) {
                if (xml.eventType == XmlPullParser.START_TAG && xml.depth == 2 && xml.getAttributeValue(null, "name") == "su_tapjack") {
                    if (xml.name != "boolean" || saved != null) return null
                    saved = xml.getAttributeValue(null, "value")?.toBooleanStrictOrNull() ?: return null
                }
            }
            saved ?: true
        }
    }

    /** A renamed manager runs the full APK behind a stub. Read its manifest without loading app code. */
    private fun hiddenVersion(apk: File): Long {
        if (!apk.isFile || apk.canonicalFile != apk) return -1
        return AssetManager::class.java.getDeclaredConstructor().newInstance().use { assets ->
            val cookie = AssetManager::class.java.getMethod("addAssetPath", String::class.java)
                .invoke(assets, apk.path) as Int
            if (cookie == 0) return -1
            assets.openXmlResourceParser(cookie, "AndroidManifest.xml").use { xml ->
                var event = xml.next()
                while (event != XmlPullParser.START_TAG && event != XmlPullParser.END_DOCUMENT) event = xml.next()
                if (event != XmlPullParser.START_TAG || xml.name != "manifest" ||
                    xml.getAttributeValue(null, "package") != STOCK) return -1
                xml.getAttributeIntValue("http://schemas.android.com/apk/res/android", "versionCode", -1).toLong()
            }
        }
    }
}
