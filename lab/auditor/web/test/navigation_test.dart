import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('tapping each nav rail destination shows its screen', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'total_evidence': 0,
          'total_verdicts': 0,
          'verdicts_by_status': {'PASS': 0, 'FAIL': 0, 'PARTIAL': 0, 'INCONCLUSIVE': 0},
        }),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(AuditorApp(apiClient: apiClient));

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
