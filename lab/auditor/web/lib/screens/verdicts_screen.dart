import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';

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
    _verdictsFuture = widget.apiClient.getVerdicts();
  }

  void _showDetail(BuildContext context, Verdict verdict) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: kSurface,
        title: Text(verdict.controlId),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(verdict.reason),
              const SizedBox(height: 8),
              Text('${verdict.saudiSource['framework']} §${verdict.saudiSource['reference']}'),
              const SizedBox(height: 8),
              Text(verdict.remediation),
            ],
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
    return FutureBuilder<List<Verdict>>(
      future: _verdictsFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final verdicts = snapshot.data!;
        return Material(
          type: MaterialType.transparency,
          child: ListView.builder(
            itemCount: verdicts.length,
            itemBuilder: (context, index) {
              final v = verdicts[index];
              return ListTile(
                leading: CircleAvatar(
                  backgroundColor: statusColor(v.status),
                  child: Text(v.status[0], style: const TextStyle(color: kBackground)),
                ),
                title: Text(v.controlId),
                subtitle: Text('${v.deviceId} · ${v.status}'),
                trailing: Text(v.status, style: TextStyle(color: statusColor(v.status))),
                onTap: () => _showDetail(context, v),
              );
            },
          ),
        );
      },
    );
  }
}
