package io.github.capitan0n.droynis.ui

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.unit.dp

/**
 * The owl-shield of the launcher icon, without its background, for the top bar and About. Same
 * shapes as res/drawable/ic_launcher_foreground.xml (108-unit canvas), moved into a 60-unit square.
 */
val DroynisLogo: ImageVector by lazy {
    val owl = addPathNodes(OWL)
    fun solid(argb: Long) = SolidColor(Color(argb))
    val teal = Brush.linearGradient(listOf(Color(0xFF3FC8BC), Color(0xFF0B6669)), Offset(54f, 28f), Offset(54f, 84f))
    ImageVector.Builder("DroynisLogo", 48.dp, 48.dp, viewportWidth = 60f, viewportHeight = 60f)
        .addGroup(translationX = -24f, translationY = -26f)
        .addPath(owl, fill = teal)
        // The rim: a stroke clipped to the inside of the shield.
        .addGroup(clipPathData = owl)
        .addPath(owl, stroke = solid(0xFF9BEFE6), strokeLineWidth = 3.4f)
        .clearGroup()
        .addPath(addPathNodes(circles(r = 10f)), fill = solid(0xFFCFF5F0))
        .addPath(addPathNodes(circles(r = 6.6f)), fill = solid(0xFFF6B940))
        .addPath(addPathNodes(circles(r = 3.3f)), fill = solid(0xFF132029))
        .addPath(addPathNodes(circles(r = 1.15f, dx = -1.4f, dy = -1.4f)), fill = solid(0xFFFFFFFF))
        .addPath(addPathNodes("M54,58.5 L57,62.5 L54,67 L51,62.5 Z"), fill = solid(0xFFD98E2B))
        // Chest feathers, which double as small check marks.
        .addPath(
            addPathNodes("M48.5,71 L51.5,73.5 L54.5,71 M53.5,71 L56.5,73.5 L59.5,71 M51,76 L54,78.5 L57,76"),
            stroke = solid(0xFF6FD9CE),
            strokeAlpha = 0.8f,
            strokeLineWidth = 1.3f,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
        )
        .clearGroup()
        .build()
}

private const val OWL =
    "M36,28 C41,31 47,35 54,35 C61,35 67,31 72,28 C74.5,34 76,41 76,48 " +
        "C76,64 67,76 54,84 C41,76 32,64 32,48 C32,41 33.5,34 36,28 Z"

/** One circle per eye, centred on (44, 52) and (64, 52), each moved by (dx, dy). */
private fun circles(r: Float, dx: Float = 0f, dy: Float = 0f): String =
    listOf(44f, 64f).joinToString(" ") { x ->
        "M${x + dx - r},${52f + dy} a$r,$r 0 1,0 ${2 * r},0 a$r,$r 0 1,0 ${-2 * r},0 Z"
    }
