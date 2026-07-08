import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';

class OverviewScreen extends StatefulWidget {
  final ApiClient apiClient;

  const OverviewScreen({super.key, required this.apiClient});

  @override
  State<OverviewScreen> createState() => _OverviewScreenState();
}

class _OverviewScreenState extends State<OverviewScreen> {
  late Future<Summary> _summaryFuture;

  @override
  void initState() {
    super.initState();
    _summaryFuture = widget.apiClient.getSummary();
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Summary>(
      future: _summaryFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final summary = snapshot.data!;
        return Padding(
          padding: const EdgeInsets.all(24),
          child: Wrap(
            spacing: 16,
            runSpacing: 16,
            children: [
              _StatCard(label: 'Total Evidence', value: '${summary.totalEvidence}'),
              _StatCard(label: 'Total Verdicts', value: '${summary.totalVerdicts}'),
              ...summary.verdictsByStatus.entries.map(
                (entry) => _StatCard(
                  label: entry.key,
                  value: '${entry.key}: ${entry.value}',
                  color: statusColor(entry.key),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _StatCard extends StatelessWidget {
  final String label;
  final String value;
  final Color? color;

  const _StatCard({required this.label, required this.value, this.color});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: kSurface,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Text(value, style: TextStyle(fontSize: 20, color: color ?? kPrimaryText)),
      ),
    );
  }
}
