import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

class VerdictsScreen extends StatefulWidget {
  final ApiClient apiClient;

  const VerdictsScreen({super.key, required this.apiClient});

  @override
  State<VerdictsScreen> createState() => _VerdictsScreenState();
}

class _VerdictsScreenState extends State<VerdictsScreen> {
  late Future<List<Verdict>> _verdictsFuture;

  @override
  void initState() {
    super.initState();
    _load();
  }

  void _load() {
    _verdictsFuture = widget.apiClient.getVerdicts();
  }

  void _showDetail(BuildContext context, Verdict verdict) {
    final color = statusColor(verdict.status);
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(kRadius)),
        title: Row(
          children: [
            Expanded(child: Text(verdict.controlId, style: const TextStyle(fontFamily: kMonospaceFontFamily, fontSize: 16))),
            StatusChip(status: verdict.status),
          ],
        ),
        content: SizedBox(
          width: 440,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.08),
                    borderRadius: BorderRadius.circular(kRadiusSm),
                    border: Border.all(color: color.withValues(alpha: 0.3)),
                  ),
                  child: Text(verdict.reason, style: Theme.of(context).textTheme.bodyMedium),
                ),
                const SizedBox(height: 16),
                _DetailRow(icon: Icons.dns_rounded, label: 'Device', value: verdict.deviceId),
                _DetailRow(
                  icon: Icons.gavel_rounded,
                  label: 'Source',
                  value: '${verdict.saudiSource['framework']} §${verdict.saudiSource['reference']}',
                ),
                const SizedBox(height: 12),
                const Divider(),
                const SizedBox(height: 12),
                Text('Remediation', style: Theme.of(context).textTheme.labelMedium),
                const SizedBox(height: 6),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.build_circle_rounded, size: 18, color: kAccent),
                    const SizedBox(width: 10),
                    Expanded(child: Text(verdict.remediation, style: Theme.of(context).textTheme.bodyMedium)),
                  ],
                ),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Close')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const ScreenHeader(
          icon: Icons.verified_rounded,
          title: 'Verdicts',
          subtitle: 'Compliance verdicts produced by the deterministic policy engine',
        ),
        Expanded(
          child: FutureBuilder<List<Verdict>>(
            future: _verdictsFuture,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return ErrorState(message: '${snapshot.error}', onRetry: () => setState(_load));
              }
              if (!snapshot.hasData) {
                return const SkeletonList();
              }
              final verdicts = snapshot.data!;
              if (verdicts.isEmpty) {
                return const EmptyState(icon: Icons.rule_rounded, message: 'No verdicts recorded yet');
              }
              return ListView.separated(
                padding: const EdgeInsets.fromLTRB(28, 8, 28, 28),
                itemCount: verdicts.length,
                separatorBuilder: (_, __) => const SizedBox(height: 10),
                itemBuilder: (context, index) {
                  final v = verdicts[index];
                  return Material(
                    color: Colors.transparent,
                    child: InkWell(
                      borderRadius: BorderRadius.circular(kRadius),
                      onTap: () => _showDetail(context, v),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                        decoration: cardDecoration(),
                        child: Row(
                          children: [
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    v.controlId,
                                    style: const TextStyle(fontFamily: kMonospaceFontFamily, fontWeight: FontWeight.w600, fontSize: 13),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(v.deviceId, style: Theme.of(context).textTheme.bodySmall),
                                ],
                              ),
                            ),
                            StatusChip(status: v.status),
                            const SizedBox(width: 8),
                            const Icon(Icons.chevron_right_rounded, color: kMutedText),
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

class _DetailRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _DetailRow({required this.icon, required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 16, color: kMutedText),
          const SizedBox(width: 10),
          SizedBox(width: 90, child: Text(label, style: Theme.of(context).textTheme.bodySmall)),
          Expanded(child: Text(value, style: Theme.of(context).textTheme.bodyMedium)),
        ],
      ),
    );
  }
}
