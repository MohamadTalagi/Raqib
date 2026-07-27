import { BrowserRouter, Routes, Route } from "react-router-dom";
import { OverviewPage } from "@/pages/OverviewPage";
import { DevicesPage } from "@/pages/DevicesPage";
import { NetworkMapPage } from "@/pages/NetworkMapPage";
import { DeviceDetailPage } from "@/pages/DeviceDetailPage";
import { EvidencePage } from "@/pages/EvidencePage";
import { VerdictsPage } from "@/pages/VerdictsPage";
import { RunScanPage } from "@/pages/RunScanPage";
import { DeviceConsolePage } from "@/pages/DeviceConsolePage";
import { ControlsPage } from "@/pages/ControlsPage";
import { ControlDetailPage } from "@/pages/ControlDetailPage";
import { NCACompliancePage } from "@/pages/NCACompliancePage";
import { DeviceAssessmentPage } from "@/pages/DeviceAssessmentPage";
import { NCAControlsPage } from "@/pages/NCAControlsPage";
import { NCAControlDetailPage } from "@/pages/NCAControlDetailPage";
import { OrganizationalCompliancePage } from "@/pages/OrganizationalCompliancePage";
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
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/network-map" element={<NetworkMapPage />} />
            <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/verdicts" element={<VerdictsPage />} />
            <Route path="/run-scan" element={<RunScanPage />} />
            <Route path="/console" element={<DeviceConsolePage />} />
            <Route path="/controls" element={<ControlsPage />} />
            <Route path="/controls/:controlId" element={<ControlDetailPage />} />
            <Route path="/nca-compliance" element={<NCACompliancePage />} />
            <Route path="/nca-compliance/devices/:deviceId" element={<DeviceAssessmentPage />} />
            <Route path="/nca-compliance/organization" element={<OrganizationalCompliancePage />} />
            <Route path="/nca-compliance/controls" element={<NCAControlsPage />} />
            <Route path="/nca-compliance/controls/:controlId" element={<NCAControlDetailPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </ErrorBoundary>
  );
}
