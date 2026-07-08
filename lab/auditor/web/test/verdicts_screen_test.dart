import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/verdicts_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

Map<String, dynamic> _verdictJson(String id, String controlId, String status) => {
      'verdict_id': id,
      'control_id': controlId,
      'device_id': 'device-insecure',
      'status': status,
      'severity': 'high',
      'evidence_ids': ['EV-2026-07-08-0015'],
      'reason': 'Default credentials accepted',
      'saudi_source': {'framework': 'CGIoT-1:2024', 'reference': '2-2-2'},
      'remediation': 'Force password change',
      'timestamp': '2026-07-08T08:06:42Z',
    };

void main() {
  testWidgets('lists verdicts with status chips and opens detail on tap', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode([_verdictJson('VD-2026-07-08-0003', 'SA-IOT-002', 'FAIL')]),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: VerdictsScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('FAIL'), findsOneWidget);
    expect(find.text('SA-IOT-002'), findsOneWidget);

    await tester.tap(find.text('SA-IOT-002'));
    await tester.pumpAndSettle();

    expect(find.text('Default credentials accepted'), findsOneWidget);
    expect(find.text('Force password change'), findsOneWidget);
  });
}
