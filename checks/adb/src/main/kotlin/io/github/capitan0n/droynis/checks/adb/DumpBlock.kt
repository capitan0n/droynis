package io.github.capitan0n.droynis.checks.adb

/** Direct fields and nested records in an AOSP DualDumpOutputStream text block. */
internal class DumpBlock(private val lines: List<String>, private val indent: String) {
    fun keys(): Set<String> = lines.asSequence()
        .filter { it.startsWith(indent) }
        .map { it.removePrefix(indent) }
        .filter { it.isNotEmpty() && !it[0].isWhitespace() && '=' in it }
        .map { it.substringBefore('=') }
        .toSet()

    fun fields(key: String) = lines.filter { it.startsWith(indent + key + "=") }

    fun records(key: String): List<DumpBlock>? {
        val headers = fields(key)
        if (headers.isEmpty()) return emptyList()
        val header = headers.singleOrNull() ?: return null
        val start = lines.indexOf(header)
        val tail = lines.subList(start + 1, lines.size)
        val end = tail.indexOfFirst { it.isNotBlank() && !it.startsWith(indent + " ") }
        if (end < 0) return null
        val body = tail.subList(0, end)
        val inner = body.firstOrNull()?.takeWhile { it == ' ' } ?: return null
        if (header == indent + key + "={" && tail[end] == indent + "}") return listOf(DumpBlock(body, inner))
        if (header != indent + key + "=[" || tail[end] != indent + "]") return null
        val result = mutableListOf<DumpBlock>()
        var i = 0
        while (i < body.size) {
            if (body[i++] != inner + "{") return null
            val from = i
            while (i < body.size && body[i].startsWith(inner + " ")) i++
            if (i == from || i == body.size || body[i++] != inner + "}") return null
            result += DumpBlock(body.subList(from, i - 1), body[from].takeWhile { it == ' ' })
        }
        return result
    }

    fun field(key: String): String? = fields(key).singleOrNull()?.substringAfter('=')
}
