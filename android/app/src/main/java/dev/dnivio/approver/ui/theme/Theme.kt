package dev.dnivio.approver.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Dnivio brand colors
private val Blue800 = Color(0xFF1E40AF)
private val Blue600 = Color(0xFF2563EB)
private val Blue100 = Color(0xFFDBEAFE)
private val Slate900 = Color(0xFF0F172A)
private val Slate700 = Color(0xFF334155)
private val Slate100 = Color(0xFFF1F5F9)

private val LightColorScheme = lightColorScheme(
    primary = Blue600,
    onPrimary = Color.White,
    primaryContainer = Blue100,
    onPrimaryContainer = Blue800,
    secondary = Slate700,
    onSecondary = Color.White,
    background = Color.White,
    onBackground = Slate900,
    surface = Color.White,
    onSurface = Slate900,
    surfaceVariant = Slate100,
    onSurfaceVariant = Slate700,
    error = Color(0xFFDC2626),
    onError = Color.White,
    errorContainer = Color(0xFFFEE2E2),
)

private val DarkColorScheme = darkColorScheme(
    primary = Blue600,
    onPrimary = Color.White,
    primaryContainer = Blue800,
    onPrimaryContainer = Blue100,
    secondary = Slate100,
    onSecondary = Slate900,
    background = Slate900,
    onBackground = Slate100,
    surface = Slate900,
    onSurface = Slate100,
    surfaceVariant = Slate700,
    onSurfaceVariant = Slate100,
    error = Color(0xFFEF4444),
    onError = Color.White,
    errorContainer = Color(0xFF7F1D1D),
)

@Composable
fun DnivioTheme(
    darkTheme: Boolean = false,
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme,
        typography = Typography(),
        content = content
    )
}
