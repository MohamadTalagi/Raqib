import 'dart:convert';

import 'package:auditor_web/api_client.dart';
import 'package:auditor_web/screens/devices_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  testWidgets('lists each device with its evidence and verdict counts', (tester) async {
    final mockClient = MockClient((request) async {
      return http.Response(
        jsonEncode([
          {'device_id': 'device-insecure', 'evidence_count': 5, 'verdict_count': 2},
          {'device_id': 'device-hardened', 'evidence_count': 3, 'verdict_count': 4},
        ]),
        200,
      );
    });
    final apiClient = ApiClient(baseUrl: 'http://auditor-api:8000', httpClient: mockClient);

    await tester.pumpWidget(MaterialApp(home: DevicesScreen(apiClient: apiClient)));
    await tester.pumpAndSettle();

    expect(find.text('device-insecure'), findsOneWidget);
    expect(find.text('device-hardened'), findsOneWidget);
  });
}
