package io.github.capitan0n.droynis.platform.shizuku;

import android.os.ParcelFileDescriptor;

/**
 * Droynis' read-only shell, which Shizuku runs as the shell user (or root). Each method runs one
 * fixed command with checked arguments; there is deliberately no way to run anything else.
 */
interface IShellService {
    /** Reserved by Shizuku, which calls it to stop the service: transaction 16777115. */
    void destroy() = 16777114;

    /** `settings --user <userId> get <table> <key>`; null when the key is unset. */
    String readSetting(String table, String key, int userId) = 1;

    /** `getenforce`: Enforcing, Permissive or Disabled. */
    String selinuxMode() = 2;

    /** `dumpsys <service>` as a stream: its output can be larger than one binder call carries. */
    ParcelFileDescriptor dumpsys(String service) = 3;
}
