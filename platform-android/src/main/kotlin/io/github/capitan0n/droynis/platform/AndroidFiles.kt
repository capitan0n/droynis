package io.github.capitan0n.droynis.platform

import io.github.capitan0n.droynis.checks.base.FileProbe
import io.github.capitan0n.droynis.core.Reading
import io.github.capitan0n.droynis.core.Source
import java.io.File

/** Existence checks only; a path SELinux hides from apps reads as absent. */
internal object AndroidFiles : FileProbe {
    override fun existing(paths: List<String>): Reading<List<String>> {
        val source = Source("File.exists() on known paths")
        return probe(source) { Reading.Value(paths.filter { File(it).exists() }, source) }
    }
}
