import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/main.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('tapping each nav rail destination shows its screen', (tester) async {
    final mockClient = MockClient((request) async {
      if (request.url.path.endsWith('/devices')) {
        return http.Response(
          jsonEncode([
            {'device_id': 'device-insecure', 'evidence_count': 5, 'verdict_count': 2},
          ]),
          200,
        );
      }
      if (request.url.path.endsWith('/evidence')) {
        return http.Response(
          jsonEncode([
            {
              'evidence_id': 'EV-2026-07-08-0013',
              'device_id': 'device-insecure',
              'test_id': 'TEST-NET-PORTSCAN',
              'tool': 'nmap',
              'tool_version': '7.95',
              'command': 'nmap -sV -p- device-insecure',
              'timestamp': '2026-07-08T08:06:42Z',
              'finding': 'Port 80 open',
              'observations': {'open_ports': [80]},
              'raw_output_path': 'document-store/raw/EV-2026-07-08-0013.txt',
              'confidence': 'high',
              'sha256': 'a' * 64,
            },
          ]),
          200,
        );
      }
      if (request.url.path.endsWith('/verdicts')) {
        return http.Response(
          jsonEncode([
            {
              'verdict_id': 'VD-2026-07-08-0003',
              'control_id': 'SA-IOT-002',
              'device_id': 'device-insecure',
              'status': 'FAIL',
              'severity': 'high',
              'evidence_ids': ['EV-2026-07-08-0015'],
              'reason': 'Default credentials accepted',
              'saudi_source': {'framework': 'CGIoT-1:2024', 'reference': '2-2-2'},
              'remediation': 'Force password change',
              'timestamp': '2026-07-08T08:06:42Z',
            },
          ]),
          200,
        );
      }
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
    expect(find.text('device-insecure'), findsOneWidget);

    await tester.tap(find.text('Evidence').last);
    await tester.pumpAndSettle();
    expect(find.text('EV-2026-07-08-0013'), findsOneWidget);

    await tester.tap(find.text('Verdicts').last);
    await tester.pumpAndSettle();
    expect(find.text('SA-IOT-002'), findsOneWidget);
  });
}
