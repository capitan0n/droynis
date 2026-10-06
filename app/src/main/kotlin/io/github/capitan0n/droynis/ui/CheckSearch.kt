package io.github.capitan0n.droynis.ui

import io.github.capitan0n.droynis.core.CheckSpec
import io.github.capitan0n.droynis.core.Finding
import java.util.Locale

/** The lower-case words of a search. */
internal fun searchWords(query: String): List<String> =
    query.lowercase(Locale.ROOT).split(WHITESPACE).filter { it.isNotEmpty() }

/**
 * True when a word of [text] starts with each of [words]: "pin" finds "PIN" but not "keeping",
 * "4008" finds "APPS-4008".
 */
internal fun matchesSearch(text: String, words: List<String>): Boolean = words.all { word ->
    var at = text.indexOf(word)
    while (at > 0 && text[at - 1].isLetterOrDigit()) at = text.indexOf(word, at + 1)
    at >= 0
}

/**
 * What a search looks through, in lower case: the check's id, title, explanation, fix, failure
 * rule and category, and after a scan its summary and evidence, so a search for an app also finds
 * the checks that named it. A copy without hyphens lets "wifi" find "Wi-Fi".
 */
internal fun searchText(spec: CheckSpec, finding: Finding?): String = buildList {
    add(spec.id)
    add(spec.title)
    add(spec.explanation)
    add(spec.remediation.text)
    spec.remediation.command?.let(::add)
    add(spec.failsWhen)
    add(spec.category.label)
    if (finding != null) {
        add(finding.summary)
        for (evidence in finding.evidence) {
            add(evidence.label)
            evidence.value?.let(::add)
            evidence.note?.let(::add)
        }
    }
}.joinToString("\n").lowercase(Locale.ROOT).let { "$it\n${it.replace("-", "")}" }

private val WHITESPACE = Regex("\\s+")
