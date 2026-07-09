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

    // Hero stat cards show the raw totals.
    expect(find.text('12'), findsOneWidget);
    expect(find.text('8'), findsOneWidget);

    // Verdict breakdown shows a status chip per non-zero status plus its
    // count — PARTIAL/INCONCLUSIVE are 0 so they're still listed in the
    // legend (all 4 statuses always render), but PASS and FAIL should each
    // show their status chip label and count.
    expect(find.text('PASS'), findsOneWidget);
    expect(find.text('FAIL'), findsOneWidget);
    expect(find.text('4'), findsNWidgets(2));
  });

  testWidgets('shows an empty state when there are no verdicts yet', (tester) async {
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

    await tester.pumpWidget(MaterialApp(home: OverviewScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('No verdicts recorded yet'), findsOneWidget);
  });

  testWidgets('shows an error state when the API call fails', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response('Internal Server Error', 500);
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: OverviewScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('Couldn\'t reach auditor-api'), findsOneWidget);
    expect(find.text('Retry'), findsOneWidget);
  });
}
