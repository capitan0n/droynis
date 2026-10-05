package io.github.capitan0n.droynis.report

import io.github.capitan0n.droynis.core.Finding
import io.github.capitan0n.droynis.core.ScanContext
import java.time.format.DateTimeFormatter

/**
 * Machine-readable report, meant for diffing scans and for tools such as jq. The layout is
 * versioned by [SCHEMA_VERSION]; findings keep catalog order so two reports line up line by line.
 * Same content rules as [MarkdownReport]: only what the scan observed plus the facts passed in.
 */
object JsonReport {

    const val SCHEMA = "droynis-report"
    const val SCHEMA_VERSION = 1

    fun render(
        context: ScanContext,
        findings: List<Finding>,
        index: HardeningIndex,
        facts: List<DeviceFact>,
        appVersion: String,
    ): String {
        val counts = findings.withoutMuted(index.muted).countByVerdict()
        val root = linkedMapOf(
            "schema" to SCHEMA,
            "schemaVersion" to SCHEMA_VERSION,
            "generator" to linkedMapOf("app" to "Droynis", "version" to appVersion),
            "scan" to linkedMapOf(
                "startedAt" to context.startedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                "sdkInt" to context.sdkInt,
                "tier" to context.capabilities.tier.name,
                "grants" to context.capabilities.grants.map { it.name }.sorted(),
            ),
            "device" to facts.associateTo(linkedMapOf()) { it.key to it.value },
            "score" to linkedMapOf(
                "value" to index.score,
                "uncapped" to index.uncappedScore,
                "grade" to index.grade?.name,
                "cappedBy" to index.cappedBy,
                "passed" to index.passed,
                "failed" to index.failed.entries.sortedByDescending { it.key }.associate { it.key.name to it.value },
                "unknown" to index.unknown,
                "unsupported" to index.unsupported,
                "muted" to index.muted,
            ),
            "verdicts" to counts.entries.associate { it.key.name to it.value },
            "findings" to findings.map { finding ->
                linkedMapOf(
                    "id" to finding.spec.id,
                    "title" to finding.spec.title,
                    "category" to finding.spec.category.name,
                    "status" to finding.status.name,
                    "verdict" to finding.verdict.name,
                    "severity" to finding.severity.name,
                    "declaredSeverity" to finding.spec.severity.name,
                    "muted" to (finding.spec.id in index.muted),
                    "summary" to finding.summary,
                    "evidence" to finding.evidence.map {
                        linkedMapOf(
                            "label" to it.label,
                            "value" to it.value,
                            "source" to it.source.method,
                            "grant" to it.source.grant?.name,
                            "note" to it.note,
                        )
                    },
                    "remediation" to finding.spec.remediation.text,
                    "elapsedMillis" to finding.elapsedMillis,
                )
            },
        )
        return buildString { write(root, indent = 0) }.trimEnd() + "\n"
    }

    private fun StringBuilder.write(value: Any?, indent: Int) {
        when (value) {
            null -> append("null")
            is String -> string(value)
            is Boolean, is Int, is Long -> append(value.toString())
            is Map<*, *> -> block('{', '}', value.entries.toList(), indent) { entry ->
                string(entry.key.toString())
                append(": ")
                write(entry.value, indent + 1)
            }
            is List<*> -> block('[', ']', value, indent) { write(it, indent + 1) }
            else -> error("Unsupported JSON value: ${value::class.simpleName}")
        }
    }

    private fun <T> StringBuilder.block(open: Char, close: Char, items: List<T>, indent: Int, item: StringBuilder.(T) -> Unit) {
        if (items.isEmpty()) {
            append(open).append(close)
            return
        }
        append(open).append('\n')
        items.forEachIndexed { i, element ->
            append("  ".repeat(indent + 1))
            item(element)
            if (i < items.lastIndex) append(',')
            append('\n')
        }
        append("  ".repeat(indent)).append(close)
    }

    private fun StringBuilder.string(text: String) {
        append('"')
        for (c in text) {
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
            }
        }
        append('"')
    }
}
