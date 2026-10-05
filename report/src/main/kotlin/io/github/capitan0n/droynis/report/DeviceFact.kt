package io.github.capitan0n.droynis.report

/**
 * One device fact for reports: [label] for people (Markdown), [key] for machines (JSON).
 * Callers must never pass hardware identifiers, phone numbers or account names.
 */
data class DeviceFact(val key: String, val label: String, val value: String)
