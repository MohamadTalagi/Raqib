import 'package:flutter/material.dart';

import '../api_client.dart';
import '../models.dart';
import '../theme.dart';

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
    _evidenceFuture = widget.apiClient.getEvidence();
  }

  void _showDetail(BuildContext context, Evidence evidence) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: kSurface,
        title: Text(evidence.evidenceId, style: const TextStyle(fontFamily: kMonospaceFontFamily)),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Finding: '),
                  Flexible(child: Text(evidence.finding)),
                ],
              ),
              const SizedBox(height: 8),
              Text('Tool: ${evidence.tool} ${evidence.toolVersion}'),
              Text('Confidence: ${evidence.confidence}'),
              const SizedBox(height: 8),
              Text(evidence.rawOutputPath, style: const TextStyle(fontFamily: kMonospaceFontFamily)),
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
    return FutureBuilder<List<Evidence>>(
      future: _evidenceFuture,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final evidence = snapshot.data!;
        return Material(
          type: MaterialType.transparency,
          child: ListView.builder(
            itemCount: evidence.length,
            itemBuilder: (context, index) {
              final e = evidence[index];
              return ListTile(
                title: Text(e.evidenceId, style: const TextStyle(fontFamily: kMonospaceFontFamily)),
                subtitle: Text('${e.deviceId} · ${e.testId} · ${e.finding}'),
                onTap: () => _showDetail(context, e),
              );
            },
          ),
        );
      },
    );
  }
}
