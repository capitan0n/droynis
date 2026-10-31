package io.github.capitan0n.droynis.ui.theme

import kotlin.math.pow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TonalPaletteTest {

    /** Every hue, at the chroma of the colorful accents and of Graphite. */
    private val palettes = (0 until 360 step 5).flatMap { hue ->
        listOf(48.0, 8.0).map { chroma -> "hue $hue, chroma $chroma" to TonalPalette(hue.toDouble(), chroma) }
    }

    @Test
    fun tonesZeroAndHundredAreBlackAndWhite() {
        for ((name, palette) in palettes) {
            assertEquals(name, 0xFF000000.toInt(), palette.argb(0))
            assertEquals(name, 0xFFFFFFFF.toInt(), palette.argb(100))
        }
    }

    @Test
    fun chromaZeroIsGrey() {
        val argb = TonalPalette(hue = 123.0, chroma = 0.0).argb(50)
        val (r, g, b) = channels(argb)
        assertTrue("got ${argb.hex()}", r == g && g == b)
    }

    @Test
    fun toneIsTheLightnessWhateverTheHue() {
        for ((name, palette) in palettes) {
            for (tone in listOf(10, 20, 30, 40, 50, 80, 90, 95)) {
                // One 8-bit step moves L* by under 0.5 in this range.
                assertEquals("$name, tone $tone", tone.toDouble(), lightness(palette.argb(tone)), 0.5)
            }
        }
    }

    @Test
    fun textRolesMeetWcagContrast() {
        for ((name, palette) in palettes) {
            // Light: primary 40 / on-primary 100; dark: primary 80 / on-primary 20.
            assertAtLeast("$name light primary", 4.5, contrast(palette.argb(40), palette.argb(100)))
            assertAtLeast("$name dark primary", 4.5, contrast(palette.argb(80), palette.argb(20)))
            // Containers: 90 / 10 in light, 30 / 90 in dark.
            assertAtLeast("$name light container", 7.0, contrast(palette.argb(90), palette.argb(10)))
            assertAtLeast("$name dark container", 4.5, contrast(palette.argb(30), palette.argb(90)))
            // Secondary text on the surface: 30 on 98 in light, 80 on 6 in dark.
            assertAtLeast("$name light variant text", 4.5, contrast(palette.argb(30), palette.argb(98)))
            assertAtLeast("$name dark variant text", 4.5, contrast(palette.argb(80), palette.argb(6)))
        }
    }

    private fun assertAtLeast(message: String, min: Double, actual: Double) =
        assertTrue("$message: contrast $actual < $min", actual >= min)

    private fun channels(argb: Int) = Triple((argb shr 16) and 0xFF, (argb shr 8) and 0xFF, argb and 0xFF)

    private fun Int.hex() = "#%06X".format(this and 0xFFFFFF)

    /** WCAG relative luminance. */
    private fun luminance(argb: Int): Double {
        val (r, g, b) = channels(argb).toList().map { c ->
            val v = c / 255.0
            if (v <= 0.04045) v / 12.92 else ((v + 0.055) / 1.055).pow(2.4)
        }
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    private fun contrast(a: Int, b: Int): Double {
        val (light, dark) = listOf(luminance(a), luminance(b)).sortedDescending()
        return (light + 0.05) / (dark + 0.05)
    }

    /** CIELAB L* of an sRGB color. */
    private fun lightness(argb: Int): Double {
        val y = luminance(argb)
        return if (y > 216.0 / 24389) 116 * Math.cbrt(y) - 16 else y * 24389.0 / 27
    }
}
