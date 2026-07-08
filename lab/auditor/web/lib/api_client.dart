import 'dart:convert';

import 'package:http/http.dart' as http;

import 'models.dart';

class ApiClient {
  final String baseUrl;
  final http.Client httpClient;

  ApiClient({required this.baseUrl, http.Client? httpClient})
      : httpClient = httpClient ?? http.Client();

  Future<List<Evidence>> getEvidence() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/evidence'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((e) => Evidence.fromJson(e as Map<String, dynamic>)).toList();
  }

  Future<List<Verdict>> getVerdicts() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/verdicts'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((v) => Verdict.fromJson(v as Map<String, dynamic>)).toList();
  }

  Future<List<Device>> getDevices() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/devices'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((d) => Device.fromJson(d as Map<String, dynamic>)).toList();
  }

  Future<Summary> getSummary() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/summary'));
    return Summary.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<List<Control>> getControls() async {
    final response = await httpClient.get(Uri.parse('$baseUrl/controls'));
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((c) => Control.fromJson(c as Map<String, dynamic>)).toList();
  }
}
