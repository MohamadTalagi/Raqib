import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test('getEvidence parses the response body into Evidence objects', () async {
    final mockClient = MockClient((request) async {
      expect(request.url.toString(), 'http://auditor-api:8000/evidence');
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
          }
        ]),
        200,
      );
    });

    final client = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);
    final result = await client.getEvidence();

    expect(result.length, 1);
    expect(result.first.evidenceId, 'EV-2026-07-08-0013');
    expect(result.first.finding, 'Port 80 open');
  });

  test('getSummary parses aggregate counts', () async {
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

    final client = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);
    final result = await client.getSummary();

    expect(result.totalEvidence, 12);
    expect(result.verdictsByStatus['PASS'], 4);
  });
}
