import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/common.dart';

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
    _load();
  }

  void _load() {
    _summaryFuture = widget.apiClient.getSummary();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const ScreenHeader(
          icon: Icons.dashboard_rounded,
          title: 'Overview',
          subtitle: 'Live compliance snapshot across all devices',
        ),
        Expanded(
          child: FutureBuilder<Summary>(
            future: _summaryFuture,
            builder: (context, snapshot) {
              if (snapshot.hasError) {
                return ErrorState(
                  message: '${snapshot.error}',
                  onRetry: () => setState(_load),
                );
              }
              if (!snapshot.hasData) {
                return const SkeletonList(rows: 2);
              }
              final summary = snapshot.data!;
              return SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(28, 8, 28, 28),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: _HeroStat(
                            icon: Icons.fact_check_rounded,
                            label: 'Total Evidence',
                            value: '${summary.totalEvidence}',
                            accent: kAccent,
                          ),
                        ),
                        const SizedBox(width: 16),
                        Expanded(
                          child: _HeroStat(
                            icon: Icons.verified_rounded,
                            label: 'Total Verdicts',
                            value: '${summary.totalVerdicts}',
                            accent: kAccent,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    Container(
                      padding: const EdgeInsets.all(20),
                      decoration: cardDecoration(),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Verdict status breakdown', style: Theme.of(context).textTheme.titleMedium),
                          const SizedBox(height: 20),
                          _VerdictBreakdown(byStatus: summary.verdictsByStatus),
                        ],
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}

class _HeroStat extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final Color accent;

  const _HeroStat({required this.icon, required this.label, required this.value, required this.accent});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: cardDecoration(),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: accent.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(kRadiusSm),
            ),
            child: Icon(icon, color: accent, size: 26),
          ),
          const SizedBox(width: 16),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(value, style: Theme.of(context).textTheme.displaySmall),
              Text(label, style: Theme.of(context).textTheme.bodySmall),
            ],
          ),
        ],
      ),
    );
  }
}

class _VerdictBreakdown extends StatelessWidget {
  final Map<String, dynamic> byStatus;

  const _VerdictBreakdown({required this.byStatus});

  @override
  Widget build(BuildContext context) {
    final total = byStatus.values.fold<int>(0, (sum, v) => sum + (v as int));
    final entries = byStatus.entries.where((e) => (e.value as int) > 0).toList();

    if (total == 0) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 24),
        child: EmptyState(icon: Icons.donut_large_rounded, message: 'No verdicts recorded yet'),
      );
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final narrow = constraints.maxWidth < 420;
        final chart = SizedBox(
          height: 160,
          width: 160,
          child: PieChart(
            PieChartData(
              sectionsSpace: 3,
              centerSpaceRadius: 46,
              sections: entries
                  .map(
                    (e) => PieChartSectionData(
                      value: (e.value as int).toDouble(),
                      color: statusColor(e.key),
                      radius: 24,
                      showTitle: false,
                    ),
                  )
                  .toList(),
            ),
          ),
        );
        final legend = Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: byStatus.entries.map((e) {
            final count = e.value as int;
            final pct = total == 0 ? 0 : (count / total * 100).round();
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Row(
                children: [
                  StatusChip(status: e.key),
                  const SizedBox(width: 12),
                  Text('$count', style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(width: 6),
                  Text('($pct%)', style: Theme.of(context).textTheme.bodySmall),
                ],
              ),
            );
          }).toList(),
        );

        if (narrow) {
          return Column(children: [chart, const SizedBox(height: 16), legend]);
        }
        return Row(
          children: [
            chart,
            const SizedBox(width: 32),
            Expanded(child: legend),
          ],
        );
      },
    );
  }
}
