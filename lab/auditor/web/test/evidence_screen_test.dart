import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/evidence_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

Map<String, dynamic> _evidenceJson(String id, String finding) => {
      'evidence_id': id,
      'device_id': 'device-insecure',
      'test_id': 'TEST-NET-PORTSCAN',
      'tool': 'nmap',
      'tool_version': '7.95',
      'command': 'nmap -sV -p- device-insecure',
      'timestamp': '2026-07-08T08:06:42Z',
      'finding': finding,
      'observations': {'open_ports': [80]},
      'raw_output_path': 'document-store/raw/$id.txt',
      'confidence': 'high',
      'sha256': 'a' * 64,
    };

void main() {
  testWidgets('lists evidence and opens a detail panel on tap', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode([_evidenceJson('EV-2026-07-08-0013', 'Port 80 open')]),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: EvidenceScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('EV-2026-07-08-0013'), findsOneWidget);

    await tester.tap(find.text('EV-2026-07-08-0013'));
    await tester.pumpAndSettle();

    expect(find.text('Port 80 open'), findsWidgets);
    expect(find.text('document-store/raw/EV-2026-07-08-0013.txt'), findsOneWidget);
  });
}
