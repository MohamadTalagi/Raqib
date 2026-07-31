import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { OverviewPage } from "@/pages/OverviewPage";
import { DevicesPage } from "@/pages/DevicesPage";
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
import { ComingSoonPage } from "@/pages/ComingSoonPage";
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
            <Route
              path="/discovery"
              element={
                <ComingSoonPage
                  title="Discovery"
                  phaseLabel="Pipeline"
                  description="Sweep the network for candidate devices - lands here in a later phase of the dashboard reorder. Use Devices in the meantime."
                />
              }
            />
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
            <Route path="/devices/:deviceId/assessment" element={<DeviceAssessmentReportPage />} />
            <Route
              path="/fingerprinting"
              element={
                <ComingSoonPage
                  title="Fingerprinting"
                  phaseLabel="Pipeline"
                  description="Reachability, ports, and service identification for the selected devices - lands here in a later phase. Use a device's own page in the meantime."
                />
              }
            />
            <Route
              path="/sa-iot-compliance"
              element={
                <ComingSoonPage
                  title="SA-IOT Compliance"
                  phaseLabel="Pipeline"
                  description="The 5-control pilot assessment, run against the selected devices - lands here in a later phase. Use Verdicts/Controls in the meantime."
                />
              }
            />
            <Route path="/nca-compliance" element={<NCACompliancePage />} />
            <Route path="/nca-compliance/devices/:deviceId" element={<DeviceAssessmentPage />} />
            <Route
              path="/vulnerability-intelligence"
              element={
                <ComingSoonPage
                  title="Vulnerability Intelligence"
                  phaseLabel="Pipeline"
                  description="Real CVE/CVSS/CISA-KEV data from a firmware manifest scan - lands here in a later phase. Still available on a device's own Firmware card today."
                />
              }
            />
            <Route path="/risk" element={<RiskAssessmentPage />} />
            <Route
              path="/remediation"
              element={
                <ComingSoonPage
                  title="Remediation"
                  phaseLabel="Pipeline"
                  description="AI-assisted remediation guidance per finding - not yet built. Each control's static remediation text is available today on its own Controls page."
                />
              }
            />

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
