import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

class EvidenceScreen extends StatefulWidget {
  final ApiClient apiClient;

  const EvidenceScreen({super.key, required this.apiClient});

  @override
  State<EvidenceScreen> createState() => _EvidenceScreenState();
}

class _EvidenceScreenState extends State<EvidenceScreen> {
  late Future<List<Evidence>> _evidenceFuture;

  @override
  void initState() {
    super.initState();
    _load();
  }

  void _load() {
    _evidenceFuture = widget.apiClient.getEvidence();
  }

  Color _confidenceColor(String confidence) {
    switch (confidence) {
      case 'high':
        return kStatusPass;
      case 'medium':
        return kStatusPartial;
      default:
        return kMutedText;
    }
  }

  void _showDetail(BuildContext context, Evidence evidence) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(kRadius)),
        title: Row(
          children: [
            const Icon(Icons.fact_check_rounded, color: kAccent, size: 20),
            const SizedBox(width: 10),
            Expanded(
              child: Text(evidence.evidenceId, style: const TextStyle(fontFamily: kMonospaceFontFamily, fontSize: 16)),
            ),
          ],
        ),
        content: SizedBox(
          width: 440,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(evidence.finding, style: Theme.of(context).textTheme.bodyLarge),
                const SizedBox(height: 16),
                const Divider(),
                const SizedBox(height: 12),
                _DetailRow(icon: Icons.dns_rounded, label: 'Device', value: evidence.deviceId),
                _DetailRow(icon: Icons.science_rounded, label: 'Test', value: evidence.testId),
                _DetailRow(icon: Icons.build_rounded, label: 'Tool', value: '${evidence.tool} ${evidence.toolVersion}'),
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 6),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Icon(Icons.verified_user_rounded, size: 16, color: kMutedText),
                      const SizedBox(width: 10),
                      SizedBox(width: 90, child: Text('Confidence', style: Theme.of(context).textTheme.bodySmall)),
                      Expanded(
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                          decoration: BoxDecoration(
                            color: _confidenceColor(evidence.confidence).withValues(alpha: 0.14),
                            borderRadius: BorderRadius.circular(999),
                          ),
                          child: Text(
                            evidence.confidence,
                            style: TextStyle(color: _confidenceColor(evidence.confidence), fontWeight: FontWeight.w700, fontSize: 12),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                const Divider(),
                const SizedBox(height: 12),
                Text('Raw output', style: Theme.of(context).textTheme.labelMedium),
                const SizedBox(height: 6),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: kSurfaceSunken,
                    borderRadius: BorderRadius.circular(kRadiusSm),
                    border: Border.all(color: kBorder),
                  ),
                  child: Text(
                    evidence.rawOutputPath,
                    style: const TextStyle(fontFamily: kMonospaceFontFamily, fontSize: 12, color: kMutedText),
                  ),
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
          icon: Icons.fact_check_rounded,
          title: 'Evidence',
          subtitle: 'Raw findings collected from every manual and automated test',
        ),
        Expanded(
          child: FutureBuilder<List<Evidence>>(
            future: _evidenceFuture,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return ErrorState(message: '${snapshot.error}', onRetry: () => setState(_load));
              }
              if (!snapshot.hasData) {
                return const SkeletonList();
              }
              final evidence = snapshot.data!;
              if (evidence.isEmpty) {
                return const EmptyState(icon: Icons.inbox_rounded, message: 'No evidence recorded yet');
              }
              return ListView.separated(
                padding: const EdgeInsets.fromLTRB(28, 8, 28, 28),
                itemCount: evidence.length,
                separatorBuilder: (_, __) => const SizedBox(height: 10),
                itemBuilder: (context, index) {
                  final e = evidence[index];
                  return Material(
                    color: Colors.transparent,
                    child: InkWell(
                      borderRadius: BorderRadius.circular(kRadius),
                      onTap: () => _showDetail(context, e),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                        decoration: cardDecoration(),
                        child: Row(
                          children: [
                            Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: _confidenceColor(e.confidence).withValues(alpha: 0.12),
                                borderRadius: BorderRadius.circular(kRadiusSm),
                              ),
                              child: Icon(Icons.description_rounded, color: _confidenceColor(e.confidence), size: 18),
                            ),
                            const SizedBox(width: 14),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    e.evidenceId,
                                    style: const TextStyle(fontFamily: kMonospaceFontFamily, fontWeight: FontWeight.w600, fontSize: 13),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    '${e.deviceId} · ${e.testId}',
                                    style: Theme.of(context).textTheme.bodySmall,
                                  ),
                                  const SizedBox(height: 4),
                                  Text(e.finding, style: Theme.of(context).textTheme.bodyMedium, maxLines: 1, overflow: TextOverflow.ellipsis),
                                ],
                              ),
                            ),
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
