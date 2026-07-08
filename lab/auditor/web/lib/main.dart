import 'package:flutter/material.dart';

import 'api_client.dart';
import 'screens/devices_screen.dart';
import 'screens/evidence_screen.dart';
import 'screens/overview_screen.dart';
import 'screens/verdicts_screen.dart';
import 'theme.dart';

void main() {
  runApp(const AuditorApp());
}

class AuditorApp extends StatelessWidget {
  final ApiClient? apiClient;

  const AuditorApp({super.key, this.apiClient});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'IoTGuard Auditor',
      theme: auditorDarkTheme,
      home: HomeShell(apiClient: apiClient),
    );
  }
}

class HomeShell extends StatefulWidget {
  final ApiClient? apiClient;

  const HomeShell({super.key, this.apiClient});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _selectedIndex = 0;
  late final ApiClient _apiClient;
  late final List<Widget> _screens;

  @override
  void initState() {
    super.initState();
    _apiClient = widget.apiClient ?? ApiClient(baseUrl: const String.fromEnvironment(
      'AUDITOR_API_URL',
      defaultValue: 'http://localhost:8000',
    ));
    _screens = [
      OverviewScreen(apiClient: _apiClient),
      DevicesScreen(apiClient: _apiClient),
      EvidenceScreen(apiClient: _apiClient),
      VerdictsScreen(apiClient: _apiClient),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: _selectedIndex,
            onDestinationSelected: (index) => setState(() => _selectedIndex = index),
            labelType: NavigationRailLabelType.all,
            destinations: const [
              NavigationRailDestination(
                icon: Icon(Icons.dashboard_outlined),
                selectedIcon: Icon(Icons.dashboard),
                label: Text('Overview'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.devices_outlined),
                selectedIcon: Icon(Icons.devices),
                label: Text('Devices'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.fact_check_outlined),
                selectedIcon: Icon(Icons.fact_check),
                label: Text('Evidence'),
              ),
              NavigationRailDestination(
                icon: Icon(Icons.verified_outlined),
                selectedIcon: Icon(Icons.verified),
                label: Text('Verdicts'),
              ),
            ],
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: _screens[_selectedIndex]),
        ],
      ),
    );
  }
}
