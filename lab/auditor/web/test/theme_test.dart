import 'package:auditor_web/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('statusColor maps each known status to its design token', () {
    expect(statusColor('PASS'), const Color(0xFF4ADE80));
    expect(statusColor('FAIL'), const Color(0xFFF87171));
    expect(statusColor('PARTIAL'), const Color(0xFFFBBF24));
    expect(statusColor('INCONCLUSIVE'), const Color(0xFF94A3B8));
  });

  test('auditorDarkTheme uses the dark security-console background', () {
    expect(auditorDarkTheme.scaffoldBackgroundColor, const Color(0xFF0F172A));
  });
}
