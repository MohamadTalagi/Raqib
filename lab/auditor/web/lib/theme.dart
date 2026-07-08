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

final ThemeData auditorDarkTheme = ThemeData(
  brightness: Brightness.dark,
  scaffoldBackgroundColor: kBackground,
  colorScheme: const ColorScheme.dark(
    primary: kAccent,
    surface: kSurface,
    onSurface: kPrimaryText,
  ),
  cardColor: kSurface,
  textTheme: const TextTheme(
    bodyMedium: TextStyle(color: kPrimaryText),
    bodySmall: TextStyle(color: kMutedText),
  ),
  fontFamily: 'Inter',
);

const String kMonospaceFontFamily = 'JetBrains Mono';
