import 'package:flutter/material.dart';

void main() {
  runApp(const AuditorApp());
}

class AuditorApp extends StatelessWidget {
  const AuditorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'IoTGuard Auditor',
      home: Scaffold(body: Center(child: Text('IoTGuard Auditor Dashboard'))),
    );
  }
}
