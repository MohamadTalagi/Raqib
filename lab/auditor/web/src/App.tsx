import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { OverviewPage } from "@/pages/OverviewPage";
import { DiscoveryPage } from "@/pages/DiscoveryPage";
import { DevicesPage } from "@/pages/DevicesPage";
import { FingerprintingPage } from "@/pages/FingerprintingPage";
import { SAIOTCompliancePage } from "@/pages/SAIOTCompliancePage";
import { VulnerabilityIntelligencePage } from "@/pages/VulnerabilityIntelligencePage";
import { RemediationPage } from "@/pages/RemediationPage";
import { ExecutiveSummaryPage } from "@/pages/ExecutiveSummaryPage";
import { NetworkMapPage } from "@/pages/NetworkMapPage";
import { DeviceDetailPage } from "@/pages/DeviceDetailPage";
import { DeviceAssessmentReportPage } from "@/pages/DeviceAssessmentReportPage";
import { EvidencePage } from "@/pages/EvidencePage";
import { VerdictsPage } from "@/pages/VerdictsPage";
import { RiskAssessmentPage } from "@/pages/RiskAssessmentPage";
import { DeviceConsolePage } from "@/pages/DeviceConsolePage";
import { ScanConsolePage } from "@/pages/ScanConsolePage";
import { ControlsPage } from "@/pages/ControlsPage";
import { ControlDetailPage } from "@/pages/ControlDetailPage";
import { NCACompliancePage } from "@/pages/NCACompliancePage";
import { DeviceAssessmentPage } from "@/pages/DeviceAssessmentPage";
import { NCAControlsPage } from "@/pages/NCAControlsPage";
import { NCAControlDetailPage } from "@/pages/NCAControlDetailPage";
import { OrganizationalCompliancePage } from "@/pages/OrganizationalCompliancePage";
import { AutomatedRunProgressPage } from "@/pages/AutomatedRunProgressPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ToastProvider } from "@/lib/useToast";

export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<OverviewPage />} />

            {/* Pipeline, in order - see lib/pipeline.ts's PIPELINE_PHASES */}
            <Route path="/discovery" element={<DiscoveryPage />} />
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
            <Route path="/devices/:deviceId/assessment" element={<DeviceAssessmentReportPage />} />
            <Route path="/fingerprinting" element={<FingerprintingPage />} />
            <Route path="/sa-iot-compliance" element={<SAIOTCompliancePage />} />
            <Route path="/nca-compliance" element={<NCACompliancePage />} />
            <Route path="/nca-compliance/devices/:deviceId" element={<DeviceAssessmentPage />} />
            <Route path="/vulnerability-intelligence" element={<VulnerabilityIntelligencePage />} />
            <Route path="/risk" element={<RiskAssessmentPage />} />
            <Route path="/remediation" element={<RemediationPage />} />
            <Route path="/executive-summary" element={<ExecutiveSummaryPage />} />
            <Route path="/automated-run/:runId" element={<AutomatedRunProgressPage />} />

            {/* /run-scan's functionality is now split across Fingerprinting
                and SA-IOT Compliance - redirect rather than 404 for anyone
                with the old URL bookmarked. */}
            <Route path="/run-scan" element={<Navigate to="/devices" replace />} />

            {/* Records - reference material, not pipeline steps */}
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/verdicts" element={<VerdictsPage />} />
            <Route path="/controls" element={<ControlsPage />} />
            <Route path="/controls/:controlId" element={<ControlDetailPage />} />
            <Route path="/nca-compliance/controls" element={<NCAControlsPage />} />
            <Route path="/nca-compliance/controls/:controlId" element={<NCAControlDetailPage />} />
            <Route path="/network-map" element={<NetworkMapPage />} />

            {/* Organization-wide - not per-device */}
            <Route path="/nca-compliance/organization" element={<OrganizationalCompliancePage />} />

            {/* Advanced tools - deliberately set apart from the guided pipeline */}
            <Route path="/scan-console" element={<ScanConsolePage />} />
            <Route path="/console" element={<DeviceConsolePage />} />

            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
