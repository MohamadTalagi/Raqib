import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/overview_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('shows total evidence and verdict-by-status counts', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode({
          'total_evidence': 12,
          'total_verdicts': 8,
          'verdicts_by_status': {'PASS': 4, 'FAIL': 4, 'PARTIAL': 0, 'INCONCLUSIVE': 0},
        }),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: OverviewScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('12'), findsOneWidget);
    expect(find.text('8'), findsOneWidget);
    expect(find.text('PASS: 4'), findsOneWidget);
    expect(find.text('FAIL: 4'), findsOneWidget);
  });
}
