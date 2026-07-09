import 'dart:convert';

import 'package:http/http.dart' as http;

import 'models.dart';

class ApiException implements Exception {
  final int statusCode;
  final String message;

  ApiException(this.statusCode, this.message);

  @override
  String toString() => 'ApiException($statusCode): $message';
}

class ApiClient {
  final String baseUrl;
  final http.Client httpClient;

  ApiClient({required this.baseUrl, http.Client? httpClient})
      : httpClient = httpClient ?? http.Client();

  Future<http.Response> _get(String path) async {
    final response = await httpClient.get(Uri.parse('$baseUrl$path'));
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ApiException(response.statusCode, response.body);
    }
    return response;
  }

  Future<List<Evidence>> getEvidence() async {
    final response = await _get('/evidence');
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((e) => Evidence.fromJson(e as Map<String, dynamic>)).toList();
  }

  Future<List<Verdict>> getVerdicts() async {
    final response = await _get('/verdicts');
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((v) => Verdict.fromJson(v as Map<String, dynamic>)).toList();
  }

  Future<List<Device>> getDevices() async {
    final response = await _get('/devices');
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((d) => Device.fromJson(d as Map<String, dynamic>)).toList();
  }

  Future<Summary> getSummary() async {
    final response = await _get('/summary');
    return Summary.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }

  Future<List<Control>> getControls() async {
    final response = await _get('/controls');
    final List<dynamic> body = jsonDecode(response.body);
    return body.map((c) => Control.fromJson(c as Map<String, dynamic>)).toList();
  }
}
