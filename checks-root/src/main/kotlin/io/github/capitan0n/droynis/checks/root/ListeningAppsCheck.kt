package io.github.capitan0n.droynis.checks.root

import io.github.capitan0n.droynis.checks.base.InstalledApp
import io.github.capitan0n.droynis.checks.base.PackageInventory
import io.github.capitan0n.droynis.checks.base.count
import io.github.capitan0n.droynis.checks.base.joinNames
import io.github.capitan0n.droynis.core.Category
import io.github.capitan0n.droynis.core.Check
import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Evidence
import io.github.capitan0n.droynis.core.Grant
import io.github.capitan0n.droynis.core.Outcome
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Remediation
import io.github.capitan0n.droynis.core.ScanContext
import io.github.capitan0n.droynis.core.Severity
import io.github.capitan0n.droynis.core.Source
import io.github.capitan0n.droynis.core.toEvidence
import kotlin.time.Duration.Companion.seconds

/** A socket waiting for connections or datagrams from other devices. */
data class OpenPort(val protocol: String, val address: String, val port: Int, val uid: Int)

/**
 * Reads the kernel's `/proc/net/{tcp,tcp6,udp,udp6}` tables:
 *
 * ```
 *   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
 *    0: 00000000:1F49 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 4567 1 …
 * ```
 *
 * Addresses are hex in the kernel's byte order (little-endian 32-bit words on Android's CPUs).
 * Kept: TCP sockets in LISTEN (0A), and unconnected UDP sockets on a fixed port (below the
 * ephemeral range, where clients bind), on any address but loopback.
 */
object ProcNetSockets {

    private val ROW = Regex(
        """^\s*\d+:\s+([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})""" +
            """\s+([0-9A-Fa-f]{2})\s+\S+\s+\S+\s+\S+\s+(\d+)\b.*$""",
    )
    private const val TCP_LISTEN = "0A"
    private const val UDP_UNCONNECTED = "07"

    /** Linux's default `ip_local_port_range` starts here; Android keeps it. */
    const val EPHEMERAL_START = 32768

    /** Null when a row is in another shape: a format change must never hide an open port. */
    fun parse(text: String, table: ProcNet): List<OpenPort>? {
        val ports = mutableListOf<OpenPort>()
        for (line in text.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("sl ")) continue
            val match = ROW.matchEntire(line) ?: return null
            val (local, port, remote, remotePort, state, uid) = match.destructured
            val localPort = port.toInt(16)
            val open = when (table.protocol) {
                "TCP" -> state.equals(TCP_LISTEN, ignoreCase = true)
                else -> state.equals(UDP_UNCONNECTED, ignoreCase = true) && isZero(remote) &&
                    remotePort.toInt(16) == 0 && localPort in 1 until EPHEMERAL_START
            }
            if (!open) continue
            val address = address(local) ?: return null
            if (isLoopback(address)) continue
            ports += OpenPort(table.protocol, display(address), localPort, uid.toIntOrNull() ?: return null)
        }
        return ports
    }

    private fun isZero(hex: String) = hex.all { it == '0' }

    /** The address as bytes in network order. */
    private fun address(hex: String): List<Int>? {
        if (hex.length % 8 != 0) return null
        return hex.chunked(8).flatMap { word -> word.chunked(2).reversed().map { it.toInt(16) } }
    }

    private fun isLoopback(bytes: List<Int>): Boolean = when (bytes.size) {
        4 -> bytes[0] == 127
        16 -> bytes == List(15) { 0 } + 1 ||
            // ::ffff:127.x.x.x, an IPv4 loopback address on an IPv6 socket
            (bytes.subList(0, 10).all { it == 0 } && bytes[10] == 0xFF && bytes[11] == 0xFF && bytes[12] == 127)
        else -> false
    }

    private fun display(bytes: List<Int>): String = when {
        bytes.size == 4 -> bytes.joinToString(".")
        bytes.all { it == 0 } -> "::"
        bytes.subList(0, 10).all { it == 0 } && bytes[10] == 0xFF && bytes[11] == 0xFF ->
            "::ffff:" + bytes.subList(12, 16).joinToString(".")
        else -> bytes.chunked(2).joinToString(":") { "%x".format(it[0] * 256 + it[1]) }
    }
}

class ListeningAppsCheck(
    private val root: RootShellProbe,
    private val packages: PackageInventory,
) : Check {

    override val spec = CheckSpec(
        id = "NETW-3301",
        category = Category.NETWORK,
        title = "Apps listening on the network",
        severity = Severity.NOTICE,
        explanation = "An app that listens on a network port accepts connections from other devices on " +
            "the same network, such as everyone on a public Wi-Fi. SSH servers, file sharing and sync " +
            "apps do this on purpose; a bug in them is then reachable by anyone nearby. Since Android " +
            "10 apps can't see each other's ports; root can.",
        remediation = Remediation(
            text = "Stop the server in apps that don't need to be reachable, or use it only on networks " +
                "you trust. Uninstall apps you don't recognize.",
        ),
        requires = setOf(Grant.ROOT),
        // Root reads share one shell, so a check may wait for others.
        timeout = 15.seconds,
        failsWhen = "a user app accepts connections from the network",
    )

    override suspend fun run(context: ScanContext): Outcome {
        val readings = ProcNet.entries.associateWith { root.procNet(it) }
        val unread = readings.filterValues { it is Reading.Unavailable }
        if (unread.isNotEmpty()) {
            return Outcome.unknown(
                "The socket tables could not be read",
                unread.map { (table, reading) -> reading.toEvidence("/proc/net/${table.file}") },
            )
        }
        val ports = mutableListOf<OpenPort>()
        var source: Source? = null
        for ((table, reading) in readings) {
            // A kernel without IPv6 has no tcp6 or udp6 table: nothing listens there.
            if (reading !is Reading.Value) continue
            source = reading.source
            ports += ProcNetSockets.parse(reading.value, table) ?: return Outcome.unknown(
                "/proc/net/${table.file} is in a format Droynis doesn't recognize",
                listOf(Evidence("/proc/net/${table.file}", null, reading.source, note = "unexpected row")),
            )
        }
        val src = source ?: return Outcome.unsupported("This kernel has no socket tables")

        val apps = (packages.installedApps() as? Reading.Value)?.value.orEmpty().filter { it.uid != null }.groupBy { it.uid }
        // System services (uids below 10000) and system apps are part of the OS: listed, not counted.
        val byUid = ports.distinctBy { listOf(it.protocol, it.port, it.uid) }.groupBy { it.uid }
        val user = byUid.filterKeys { uid -> uid % PER_USER_RANGE >= FIRST_APP && apps[uid]?.all { it.isSystem } != true }
        val system = byUid - user.keys

        val evidence = buildList {
            add(Evidence("Open ports", ports.size.toString(), src))
            user.forEach { (uid, open) -> add(Evidence("Listening app", name(uid, apps), src, note = describe(open))) }
            if (system.isNotEmpty()) add(Evidence("System services listening", system.values.sumOf { it.size }.toString(), src, note = describe(system.values.flatten())))
        }
        if (user.isEmpty()) return Outcome.pass("No user app accepts connections from the network", evidence)
        val names = user.map { (uid, open) -> "${name(uid, apps, withPackage = false)} (${describe(open)})" }
        val verb = if (user.size == 1) "accepts" else "accept"
        return Outcome.fail("${count(user.size, "app")} $verb connections from the network: ${names.joinNames()}", evidence)
    }

    private fun name(uid: Int, apps: Map<Int?, List<InstalledApp>>, withPackage: Boolean = true): String =
        apps[uid]?.joinToString { if (withPackage) "${packages.label(it.packageName)} (${it.packageName})" else packages.label(it.packageName) }
            ?: "uid $uid"

    private fun describe(open: List<OpenPort>): String =
        open.sortedWith(compareBy({ it.protocol }, { it.port })).joinToString { "${it.protocol} ${it.port} on ${it.address}" }

    private companion object {
        const val PER_USER_RANGE = 100_000
        const val FIRST_APP = 10_000
    }
}
