import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';

class DevicesScreen extends StatefulWidget {
  final ApiClient apiClient;

  const DevicesScreen({super.key, required this.apiClient});

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  late Future<List<Device>> _devicesFuture;

  @override
  void initState() {
    super.initState();
    _devicesFuture = widget.apiClient.getDevices();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<Device>>(
      future: _devicesFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final devices = snapshot.data!;
        return Material(
          type: MaterialType.transparency,
          child: ListView.builder(
            itemCount: devices.length,
            itemBuilder: (context, index) {
              final device = devices[index];
              return ListTile(
                leading: const Icon(Icons.devices_outlined),
                title: Text(device.deviceId),
                subtitle: Text(
                  '${device.evidenceCount} evidence · ${device.verdictCount} verdicts',
                ),
              );
            },
          ),
        );
      },
    );
  }
}
