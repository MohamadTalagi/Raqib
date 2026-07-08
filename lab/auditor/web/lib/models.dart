class Evidence {
  final String evidenceId;
  final String deviceId;
  final String testId;
  final String tool;
  final String toolVersion;
  final String command;
  final String timestamp;
  final String finding;
  final Map<String, dynamic> observations;
  final String rawOutputPath;
  final String confidence;
  final String sha256;

  Evidence({
    required this.evidenceId,
    required this.deviceId,
    required this.testId,
    required this.tool,
    required this.toolVersion,
    required this.command,
    required this.timestamp,
    required this.finding,
    required this.observations,
    required this.rawOutputPath,
    required this.confidence,
    required this.sha256,
  });

  factory Evidence.fromJson(Map<String, dynamic> json) {
    return Evidence(
      evidenceId: json['evidence_id'] as String,
      deviceId: json['device_id'] as String,
      testId: json['test_id'] as String,
      tool: json['tool'] as String,
      toolVersion: json['tool_version'] as String,
      command: json['command'] as String,
      timestamp: json['timestamp'] as String,
      finding: json['finding'] as String,
      observations: json['observations'] as Map<String, dynamic>,
      rawOutputPath: json['raw_output_path'] as String,
      confidence: json['confidence'] as String,
      sha256: json['sha256'] as String,
    );
  }
}

class Verdict {
  final String verdictId;
  final String controlId;
  final String deviceId;
  final String status;
  final String severity;
  final List<dynamic> evidenceIds;
  final String reason;
  final Map<String, dynamic> saudiSource;
  final String remediation;
  final String timestamp;

  Verdict({
    required this.verdictId,
    required this.controlId,
    required this.deviceId,
    required this.status,
    required this.severity,
    required this.evidenceIds,
    required this.reason,
    required this.saudiSource,
    required this.remediation,
    required this.timestamp,
  });

  factory Verdict.fromJson(Map<String, dynamic> json) {
    return Verdict(
      verdictId: json['verdict_id'] as String,
      controlId: json['control_id'] as String,
      deviceId: json['device_id'] as String,
      status: json['status'] as String,
      severity: json['severity'] as String,
      evidenceIds: json['evidence_ids'] as List<dynamic>,
      reason: json['reason'] as String,
      saudiSource: json['saudi_source'] as Map<String, dynamic>,
      remediation: json['remediation'] as String,
      timestamp: json['timestamp'] as String,
    );
  }
}

class Device {
  final String deviceId;
  final int evidenceCount;
  final int verdictCount;

  Device({
    required this.deviceId,
    required this.evidenceCount,
    required this.verdictCount,
  });

  factory Device.fromJson(Map<String, dynamic> json) {
    return Device(
      deviceId: json['device_id'] as String,
      evidenceCount: json['evidence_count'] as int,
      verdictCount: json['verdict_count'] as int,
    );
  }
}

class Summary {
  final int totalEvidence;
  final int totalVerdicts;
  final Map<String, dynamic> verdictsByStatus;

  Summary({
    required this.totalEvidence,
    required this.totalVerdicts,
    required this.verdictsByStatus,
  });

  factory Summary.fromJson(Map<String, dynamic> json) {
    return Summary(
      totalEvidence: json['total_evidence'] as int,
      totalVerdicts: json['total_verdicts'] as int,
      verdictsByStatus: json['verdicts_by_status'] as Map<String, dynamic>,
    );
  }
}

class Control {
  final String controlId;
  final String title;
  final Map<String, dynamic> saudiSource;
  final String remediation;

  Control({
    required this.controlId,
    required this.title,
    required this.saudiSource,
    required this.remediation,
  });

  factory Control.fromJson(Map<String, dynamic> json) {
    return Control(
      controlId: json['control_id'] as String,
      title: json['title'] as String,
      saudiSource: json['saudi_source'] as Map<String, dynamic>,
      remediation: json['remediation'] as String,
    );
  }
}
