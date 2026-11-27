package io.github.capitan0n.droynis.platform

import android.database.sqlite.SQLiteDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.capitan0n.droynis.platform.root.RootConfigReader
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RootConfigReaderTest {
    @Test
    fun readsCommittedWalFiltersProfilesAndUnderstandsFrameworkScopeMigration() {
        val dir = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir
        val path = File.createTempFile("lsposed-test-", ".db", dir)
        try {
            SQLiteDatabase.openOrCreateDatabase(path, null).use { db ->
                db.enableWriteAheadLogging()
                db.execSQL("CREATE TABLE modules(mid INTEGER PRIMARY KEY, module_pkg_name TEXT, enabled INTEGER)")
                db.execSQL("CREATE TABLE scope(mid INTEGER, app_pkg_name TEXT, user_id INTEGER)")
                db.execSQL("INSERT INTO modules VALUES (1,'test.mod',1),(2,'test.disabled',0),(3,'test.empty',1),(4,'lspd',1)")
                db.execSQL("INSERT INTO scope VALUES (1,'android',0),(1,'com.example.privateapp',10),(2,'system',0)")
                db.version = 2
                assertEquals(listOf("module\ttest.empty\t", "module\ttest.mod\tsystem"), RootConfigReader.moduleScopes(0, path.path))
                db.version = 4
                assertEquals(listOf("module\ttest.empty\t", "module\ttest.mod\tandroid"), RootConfigReader.moduleScopes(0, path.path))
                assertEquals(listOf("module\ttest.mod\tcom.example.privateapp"), RootConfigReader.moduleScopes(10, path.path))
                db.version = 5
                assertNull(RootConfigReader.moduleScopes(0, path.path))
            }
        } finally {
            SQLiteDatabase.deleteDatabase(path)
        }
    }
}
