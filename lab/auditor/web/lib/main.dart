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
      debugShowCheckedModeBanner: false,
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

  static const _titles = ['Overview', 'Devices', 'Evidence', 'Verdicts'];

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
          SizedBox(
            width: 220,
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(vertical: 24, horizontal: 20),
                  alignment: Alignment.centerLeft,
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: kAccent.withValues(alpha: 0.14),
                          borderRadius: BorderRadius.circular(kRadiusSm),
                        ),
                        child: const Icon(Icons.shield_rounded, color: kAccent, size: 22),
                      ),
                      const SizedBox(width: 10),
                      Flexible(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              'IoTGuard',
                              style: Theme.of(context).textTheme.titleLarge,
                              overflow: TextOverflow.ellipsis,
                            ),
                            const Text(
                              'AUDITOR',
                              style: TextStyle(color: kMutedText, fontSize: 10, letterSpacing: 2, fontWeight: FontWeight.w700),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1),
                Expanded(
                  child: NavigationRail(
                    extended: true,
                    minExtendedWidth: 220,
                    backgroundColor: Colors.transparent,
                    selectedIndex: _selectedIndex,
                    onDestinationSelected: (index) => setState(() => _selectedIndex = index),
                    labelType: NavigationRailLabelType.none,
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
                ),
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: const BoxDecoration(color: kStatusPass, shape: BoxShape.circle),
                      ),
                      const SizedBox(width: 8),
                      Text('Live', style: Theme.of(context).textTheme.bodySmall),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Container(
                  height: 56,
                  padding: const EdgeInsets.symmetric(horizontal: 28),
                  alignment: Alignment.centerLeft,
                  decoration: const BoxDecoration(
                    border: Border(bottom: BorderSide(color: kBorderSubtle)),
                  ),
                  child: Text(_titles[_selectedIndex], style: Theme.of(context).textTheme.labelMedium),
                ),
                Expanded(child: _screens[_selectedIndex]),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
