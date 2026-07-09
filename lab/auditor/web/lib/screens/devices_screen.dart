import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

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
    _load();
  }

  void _load() {
    _devicesFuture = widget.apiClient.getDevices();
  }

  (IconData, Color) _postureFor(String deviceId) {
    if (deviceId.contains('insecure')) return (Icons.gpp_bad_rounded, kStatusFail);
    if (deviceId.contains('partial')) return (Icons.gpp_maybe_rounded, kStatusPartial);
    if (deviceId.contains('hardened')) return (Icons.gpp_good_rounded, kStatusPass);
    return (Icons.developer_board_rounded, kAccent);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const ScreenHeader(
          icon: Icons.devices_rounded,
          title: 'Devices',
          subtitle: 'Every device and broker seen in the evidence corpus',
        ),
        Expanded(
          child: FutureBuilder<List<Device>>(
            future: _devicesFuture,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return ErrorState(message: '${snapshot.error}', onRetry: () => setState(_load));
              }
              if (!snapshot.hasData) {
                return const SkeletonList();
              }
              final devices = snapshot.data!;
              if (devices.isEmpty) {
                return const EmptyState(icon: Icons.devices_other_rounded, message: 'No devices recorded yet');
              }
              return ListView.separated(
                padding: const EdgeInsets.fromLTRB(28, 8, 28, 28),
                itemCount: devices.length,
                separatorBuilder: (_, __) => const SizedBox(height: 10),
                itemBuilder: (context, index) {
                  final device = devices[index];
                  final (icon, color) = _postureFor(device.deviceId);
                  return Material(
                    color: Colors.transparent,
                    child: InkWell(
                      borderRadius: BorderRadius.circular(kRadius),
                      onTap: () {},
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                        decoration: cardDecoration(),
                        child: Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: color.withValues(alpha: 0.12),
                                borderRadius: BorderRadius.circular(kRadiusSm),
                              ),
                              child: Icon(icon, color: color, size: 20),
                            ),
                            const SizedBox(width: 14),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    device.deviceId,
                                    style: const TextStyle(fontFamily: kMonospaceFontFamily, fontWeight: FontWeight.w600, fontSize: 13),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    '${device.evidenceCount} evidence · ${device.verdictCount} verdicts',
                                    style: Theme.of(context).textTheme.bodySmall,
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  );
                },
              );
            },
          ),
        ),
      ],
    );
  }
}
