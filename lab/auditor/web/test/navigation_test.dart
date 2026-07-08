import 'package:auditor_web/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('tapping each nav rail destination shows its screen', (tester) async {
    await tester.pumpWidget(const AuditorApp());

    expect(find.text('Overview'), findsWidgets);

    await tester.tap(find.text('Devices').last);
    await tester.pumpAndSettle();
    expect(find.text('Devices Screen'), findsOneWidget);

    await tester.tap(find.text('Evidence').last);
    await tester.pumpAndSettle();
    expect(find.text('Evidence Screen'), findsOneWidget);

    await tester.tap(find.text('Verdicts').last);
    await tester.pumpAndSettle();
    expect(find.text('Verdicts Screen'), findsOneWidget);
  });
}
