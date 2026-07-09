import 'package:flutter/material.dart';

const Color kBackground = Color(0xFF0F172A);
const Color kSurface = Color(0xFF1E293B);
const Color kPrimaryText = Color(0xFFF1F5F9);
const Color kMutedText = Color(0xFF94A3B8);
const Color kAccent = Color(0xFF22D3EE);
const Color kStatusPass = Color(0xFF4ADE80);
const Color kStatusFail = Color(0xFFF87171);
const Color kStatusPartial = Color(0xFFFBBF24);
const Color kStatusInconclusive = Color(0xFF94A3B8);

// Additional tokens for the richer UI surface (cards, borders, hover/elevated
// states) — layered above the base 5 tokens rather than replacing them, so
// existing exact-color tests keep passing.
const Color kSurfaceRaised = Color(0xFF263449); // one step lighter than kSurface
const Color kSurfaceSunken = Color(0xFF0B1220); // one step darker than kBackground
const Color kBorder = Color(0xFF334155);
const Color kBorderSubtle = Color(0xFF1E293B);
const Color kAccentMuted = Color(0xFF0E7490);

Color statusColor(String status) {
  switch (status) {
    case 'PASS':
      return kStatusPass;
    case 'FAIL':
      return kStatusFail;
    case 'PARTIAL':
      return kStatusPartial;
    default:
      return kStatusInconclusive;
  }
}

IconData statusIcon(String status) {
  switch (status) {
    case 'PASS':
      return Icons.check_circle;
    case 'FAIL':
      return Icons.cancel;
    case 'PARTIAL':
      return Icons.warning_rounded;
    default:
      return Icons.help_rounded;
  }
}

final ThemeData auditorDarkTheme = ThemeData(
  brightness: Brightness.dark,
  scaffoldBackgroundColor: kBackground,
  colorScheme: const ColorScheme.dark(
    primary: kAccent,
    secondary: kAccentMuted,
    surface: kSurface,
    onSurface: kPrimaryText,
    outline: kBorder,
  ),
  cardColor: kSurface,
  dividerColor: kBorderSubtle,
  textTheme: const TextTheme(
    displaySmall: TextStyle(color: kPrimaryText, fontWeight: FontWeight.w700, letterSpacing: -0.5),
    headlineSmall: TextStyle(color: kPrimaryText, fontWeight: FontWeight.w700),
    titleLarge: TextStyle(color: kPrimaryText, fontWeight: FontWeight.w600),
    titleMedium: TextStyle(color: kPrimaryText, fontWeight: FontWeight.w600),
    bodyLarge: TextStyle(color: kPrimaryText),
    bodyMedium: TextStyle(color: kPrimaryText),
    bodySmall: TextStyle(color: kMutedText),
    labelLarge: TextStyle(color: kPrimaryText, fontWeight: FontWeight.w600, letterSpacing: 0.2),
    labelMedium: TextStyle(color: kMutedText, fontWeight: FontWeight.w600, letterSpacing: 0.6),
  ),
  iconTheme: const IconThemeData(color: kMutedText),
  fontFamily: 'Inter',
  navigationRailTheme: const NavigationRailThemeData(
    backgroundColor: kSurfaceSunken,
    selectedIconTheme: IconThemeData(color: kAccent),
    unselectedIconTheme: IconThemeData(color: kMutedText),
    selectedLabelTextStyle: TextStyle(color: kAccent, fontWeight: FontWeight.w600, fontSize: 12),
    unselectedLabelTextStyle: TextStyle(color: kMutedText, fontSize: 12),
    indicatorColor: Color(0x2622D3EE),
  ),
  dialogTheme: const DialogThemeData(backgroundColor: kSurfaceRaised),
);

const String kMonospaceFontFamily = 'JetBrains Mono';

const double kRadius = 12;
const double kRadiusSm = 8;
const double kSpace = 8;

/// Rounded, bordered card decoration shared by every list/stat card so the
/// whole app reads as one consistent surface language.
BoxDecoration cardDecoration({bool raised = false}) {
  return BoxDecoration(
    color: raised ? kSurfaceRaised : kSurface,
    borderRadius: BorderRadius.circular(kRadius),
    border: Border.all(color: kBorder, width: 1),
  );
}
