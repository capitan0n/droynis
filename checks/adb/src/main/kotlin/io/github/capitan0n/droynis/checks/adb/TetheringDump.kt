package io.github.capitan0n.droynis.checks.adb

/** Read only the current state table. Configuration, upstream interfaces and logs also name interfaces. */
object TetheringDump {
    private val row = Regex("""([a-zA-Z0-9_.-]+) - (AvailableState|UnavailableState|TetheredState|LocalHotspotState) - lastError = [0-9]+""")
    private val usb = Regex("""(?:rndis|usb|ncm)[0-9]+""")
    private val bluetooth = Regex("""(?:bt-pan|bnep[0-9]+)""")
    private val wifi = Regex("""(?:wlan|ap|swlan|softap)[0-9]+""")
    private val ethernet = Regex("""eth[0-9]+""")

    fun active(text: String): Set<String>? {
        val lines = dumpLines(text)
        val start = lines.indices.singleOrNull { lines[it].trim() == "Tether state:" } ?: return null
        val active = mutableSetOf<String>()
        for (i in start + 1 until lines.size) {
            val line = lines[i].trim()
            if (line == "Upstream wanted: true" || line == "Upstream wanted: false") return active
            val (iface, state) = row.matchEntire(line)?.destructured ?: return null
            if (state == "TetheredState") active += when {
                usb.matches(iface) -> "USB"
                bluetooth.matches(iface) -> "Bluetooth"
                wifi.matches(iface) -> "Wi-Fi"
                ethernet.matches(iface) -> "Ethernet"
                else -> "another interface"
            }
        }
        return null
    }
}
