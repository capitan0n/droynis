package io.github.capitan0n.droynis.ui.theme

import kotlin.math.cos
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * One hue at every tone, as in Material 3's tonal palettes. A tone is the CIELAB lightness, from 0
 * (black) to 100 (white), so two tones have the same contrast whatever the hue: every accent built
 * from these palettes reads as well as the brand teal.
 */
internal class TonalPalette(private val hue: Double, private val chroma: Double) {

    /** ARGB of [tone]: the palette's chroma, or the most that sRGB can show at that tone. */
    fun argb(tone: Int): Int = lchToArgb(tone.toDouble(), chroma, hue)
}

/** CIE LCh(ab) to opaque sRGB; lowers the chroma until the color fits, so lightness stays exact. */
internal fun lchToArgb(lightness: Double, chroma: Double, hue: Double): Int {
    if (lightness <= 0.0) return BLACK
    if (lightness >= 100.0) return WHITE
    val radians = Math.toRadians(hue)
    fun at(c: Double) = labToLinearSrgb(lightness, c * cos(radians), c * sin(radians))

    var best = at(chroma)
    if (!best.inGamut()) {
        // Grey (chroma 0) always fits; search for the highest chroma that still does.
        var low = 0.0
        var high = chroma
        best = at(0.0)
        repeat(GAMUT_STEPS) {
            val mid = (low + high) / 2
            val candidate = at(mid)
            if (candidate.inGamut()) {
                low = mid
                best = candidate
            } else {
                high = mid
            }
        }
    }
    return (0xFF shl 24) or (channel(best[0]) shl 16) or (channel(best[1]) shl 8) or channel(best[2])
}

/** CIELAB (D65 white) to linear sRGB; channels outside 0..1 mean sRGB can't show the color. */
private fun labToLinearSrgb(l: Double, a: Double, b: Double): DoubleArray {
    val fy = (l + 16) / 116
    val x = WHITE_X * labInverse(fy + a / 500)
    val y = if (l > KAPPA * EPSILON) fy * fy * fy else l / KAPPA
    val z = WHITE_Z * labInverse(fy - b / 200)
    return doubleArrayOf(
        3.2404542 * x - 1.5371385 * y - 0.4985314 * z,
        -0.9692660 * x + 1.8760108 * y + 0.0415560 * z,
        0.0556434 * x - 0.2040259 * y + 1.0572252 * z,
    )
}

private fun labInverse(t: Double): Double {
    val cube = t * t * t
    return if (cube > EPSILON) cube else (116 * t - 16) / KAPPA
}

private fun DoubleArray.inGamut() = all { it >= -GAMUT_SLACK && it <= 1 + GAMUT_SLACK }

/** Linear channel to its 8-bit sRGB value. */
private fun channel(linear: Double): Int {
    val v = linear.coerceIn(0.0, 1.0)
    val encoded = if (v <= 0.0031308) 12.92 * v else 1.055 * v.pow(1 / 2.4) - 0.055
    return (encoded * 255).roundToInt()
}

private const val BLACK = 0xFF000000.toInt()
private const val WHITE = 0xFFFFFFFF.toInt()
private const val EPSILON = 216.0 / 24389
private const val KAPPA = 24389.0 / 27
private const val WHITE_X = 0.95047
private const val WHITE_Z = 1.08883
private const val GAMUT_SLACK = 1e-4
private const val GAMUT_STEPS = 24
