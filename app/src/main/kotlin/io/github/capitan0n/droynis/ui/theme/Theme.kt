package io.github.capitan0n.droynis.ui.theme

import android.content.Context
import android.os.Build
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/** The user's theme choice; stored by the view model. */
enum class ThemeMode { SYSTEM, LIGHT, DARK }

/**
 * The user's accent color; stored by the view model. No red, yellow or green: those are the status
 * colors, and a button in one of them would read as a result.
 */
enum class ThemeAccent {
    /** The brand teal of the launcher icon. */
    TEAL,
    BLUE,
    PURPLE,
    PINK,
    /** Nearly grey, for a quieter look. */
    GRAPHITE,

    /** The colors Android picks from the wallpaper; Android 12 and later. */
    WALLPAPER,
    ;

    /** False for [WALLPAPER] before Android 12, which has no wallpaper colors. */
    val available: Boolean get() = this != WALLPAPER || Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
}

// Brand: deep teal with an indigo accent, matching the launcher icon.
private val LightColors = lightColorScheme(
    primary = Color(0xFF00696B),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF9CF1F2),
    onPrimaryContainer = Color(0xFF002020),
    secondary = Color(0xFF4A6363),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCCE8E8),
    onSecondaryContainer = Color(0xFF051F20),
    tertiary = Color(0xFF4B5C92),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFDBE1FF),
    onTertiaryContainer = Color(0xFF01174B),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF4FBFA),
    onBackground = Color(0xFF161D1D),
    surface = Color(0xFFF4FBFA),
    onSurface = Color(0xFF161D1D),
    surfaceVariant = Color(0xFFDAE4E4),
    onSurfaceVariant = Color(0xFF3F4948),
    outline = Color(0xFF6F7979),
    outlineVariant = Color(0xFFBEC8C8),
    inverseSurface = Color(0xFF2B3231),
    inverseOnSurface = Color(0xFFECF2F1),
    inversePrimary = Color(0xFF80D4D5),
    surfaceDim = Color(0xFFD5DBDA),
    surfaceBright = Color(0xFFF4FBFA),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFEFF5F4),
    surfaceContainer = Color(0xFFE9EFEE),
    surfaceContainerHigh = Color(0xFFE3E9E9),
    surfaceContainerHighest = Color(0xFFDDE4E3),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF80D4D5),
    onPrimary = Color(0xFF003737),
    primaryContainer = Color(0xFF004F50),
    onPrimaryContainer = Color(0xFF9CF1F2),
    secondary = Color(0xFFB0CCCC),
    onSecondary = Color(0xFF1B3435),
    secondaryContainer = Color(0xFF324B4B),
    onSecondaryContainer = Color(0xFFCCE8E8),
    tertiary = Color(0xFFB4C5FF),
    onTertiary = Color(0xFF1A2D60),
    tertiaryContainer = Color(0xFF334478),
    onTertiaryContainer = Color(0xFFDBE1FF),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0E1514),
    onBackground = Color(0xFFDDE4E3),
    surface = Color(0xFF0E1514),
    onSurface = Color(0xFFDDE4E3),
    surfaceVariant = Color(0xFF3F4948),
    onSurfaceVariant = Color(0xFFBEC8C8),
    outline = Color(0xFF889392),
    outlineVariant = Color(0xFF3F4948),
    inverseSurface = Color(0xFFDDE4E3),
    inverseOnSurface = Color(0xFF2B3231),
    inversePrimary = Color(0xFF00696B),
    surfaceDim = Color(0xFF0E1514),
    surfaceBright = Color(0xFF343A3A),
    surfaceContainerLowest = Color(0xFF090F0F),
    surfaceContainerLow = Color(0xFF161D1D),
    surfaceContainer = Color(0xFF1A2121),
    surfaceContainerHigh = Color(0xFF252B2B),
    surfaceContainerHighest = Color(0xFF2F3636),
)

/**
 * Status colors stay the same in light and dark mode, so a green tick means the same thing
 * everywhere. They always come with an icon and a label, never as color alone.
 */
object StatusColors {
    val Good = Color(0xFF0CA30C)
    val Warning = Color(0xFFFAB219)
    val Critical = Color(0xFFD03B3B)

    /** Glyph drawn on top of each status color; dark on yellow for contrast. */
    val OnGood = Color(0xFFFFFFFF)
    val OnWarning = Color(0xFF2B2000)
    val OnCritical = Color(0xFFFFFFFF)
}

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

private val AppTypography = Typography().run {
    copy(
        displayLarge = displayLarge.copy(fontWeight = FontWeight.SemiBold),
        displayMedium = displayMedium.copy(fontWeight = FontWeight.SemiBold),
        headlineMedium = headlineMedium.copy(fontWeight = FontWeight.SemiBold),
        headlineSmall = headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelLarge = labelLarge.copy(fontWeight = FontWeight.SemiBold),
    )
}

/** Same in every accent, so an error looks the same whatever the user picked. */
private val ErrorLight = Color(0xFFBA1A1A)
private val OnErrorLight = Color(0xFFFFFFFF)
private val ErrorContainerLight = Color(0xFFFFDAD6)
private val OnErrorContainerLight = Color(0xFF410002)
private val ErrorDark = Color(0xFFFFB4AB)
private val OnErrorDark = Color(0xFF690005)
private val ErrorContainerDark = Color(0xFF93000A)
private val OnErrorContainerDark = Color(0xFFFFDAD6)

/**
 * A full scheme around [hue] (CIELAB degrees), with Material 3's tones for each role; [chroma] sets
 * how colorful the accent is. Secondary is a muted version of the same hue, tertiary is 60° on.
 */
internal fun accentColorScheme(hue: Double, chroma: Double, dark: Boolean): ColorScheme {
    val p = TonalPalette(hue, chroma)
    val s = TonalPalette(hue, minOf(chroma, 16.0))
    val t = TonalPalette(hue + 60, minOf(chroma, 24.0))
    val n = TonalPalette(hue, minOf(chroma / 4, 4.0))
    val nv = TonalPalette(hue, minOf(chroma / 2, 8.0))
    fun TonalPalette.at(tone: Int) = Color(argb(tone))
    return if (dark) {
        darkColorScheme(
            primary = p.at(80), onPrimary = p.at(20), primaryContainer = p.at(30), onPrimaryContainer = p.at(90),
            secondary = s.at(80), onSecondary = s.at(20), secondaryContainer = s.at(30), onSecondaryContainer = s.at(90),
            tertiary = t.at(80), onTertiary = t.at(20), tertiaryContainer = t.at(30), onTertiaryContainer = t.at(90),
            error = ErrorDark, onError = OnErrorDark,
            errorContainer = ErrorContainerDark, onErrorContainer = OnErrorContainerDark,
            background = n.at(6), onBackground = n.at(90), surface = n.at(6), onSurface = n.at(90),
            surfaceVariant = nv.at(30), onSurfaceVariant = nv.at(80), outline = nv.at(60), outlineVariant = nv.at(30),
            inverseSurface = n.at(90), inverseOnSurface = n.at(20), inversePrimary = p.at(40), surfaceTint = p.at(80),
            surfaceDim = n.at(6), surfaceBright = n.at(24),
            surfaceContainerLowest = n.at(4), surfaceContainerLow = n.at(10), surfaceContainer = n.at(12),
            surfaceContainerHigh = n.at(17), surfaceContainerHighest = n.at(22),
        )
    } else {
        lightColorScheme(
            primary = p.at(40), onPrimary = p.at(100), primaryContainer = p.at(90), onPrimaryContainer = p.at(10),
            secondary = s.at(40), onSecondary = s.at(100), secondaryContainer = s.at(90), onSecondaryContainer = s.at(10),
            tertiary = t.at(40), onTertiary = t.at(100), tertiaryContainer = t.at(90), onTertiaryContainer = t.at(10),
            error = ErrorLight, onError = OnErrorLight,
            errorContainer = ErrorContainerLight, onErrorContainer = OnErrorContainerLight,
            background = n.at(98), onBackground = n.at(10), surface = n.at(98), onSurface = n.at(10),
            surfaceVariant = nv.at(90), onSurfaceVariant = nv.at(30), outline = nv.at(50), outlineVariant = nv.at(80),
            inverseSurface = n.at(20), inverseOnSurface = n.at(95), inversePrimary = p.at(80), surfaceTint = p.at(40),
            surfaceDim = n.at(87), surfaceBright = n.at(98),
            surfaceContainerLowest = n.at(100), surfaceContainerLow = n.at(96), surfaceContainer = n.at(94),
            surfaceContainerHigh = n.at(92), surfaceContainerHighest = n.at(90),
        )
    }
}

/** The scheme for [accent]; wallpaper colors fall back to teal before Android 12. */
fun colorSchemeFor(accent: ThemeAccent, dark: Boolean, context: Context): ColorScheme = when (accent) {
    ThemeAccent.TEAL -> if (dark) DarkColors else LightColors
    ThemeAccent.BLUE -> accentColorScheme(hue = 265.0, chroma = 48.0, dark = dark)
    ThemeAccent.PURPLE -> accentColorScheme(hue = 305.0, chroma = 48.0, dark = dark)
    ThemeAccent.PINK -> accentColorScheme(hue = 355.0, chroma = 48.0, dark = dark)
    ThemeAccent.GRAPHITE -> accentColorScheme(hue = 250.0, chroma = 8.0, dark = dark)
    ThemeAccent.WALLPAPER -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else {
        if (dark) DarkColors else LightColors
    }
}

@Composable
fun DroynisTheme(darkTheme: Boolean, accent: ThemeAccent = ThemeAccent.TEAL, content: @Composable () -> Unit) {
    val context = LocalContext.current
    MaterialTheme(
        colorScheme = remember(accent, darkTheme, context) { colorSchemeFor(accent, darkTheme, context) },
        shapes = AppShapes,
        typography = AppTypography,
        content = content,
    )
}

/** True when the current color scheme is dark, whatever the reason (system or user choice). */
val isDarkTheme: Boolean
    @Composable get() = MaterialTheme.colorScheme.surface.luminance() < 0.5f
