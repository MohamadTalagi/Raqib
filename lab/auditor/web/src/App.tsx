import { BrowserRouter, Routes, Route } from "react-router-dom";
import { OverviewPage } from "@/pages/OverviewPage";
import { DevicesPage } from "@/pages/DevicesPage";
import { DeviceDetailPage } from "@/pages/DeviceDetailPage";
import { EvidencePage } from "@/pages/EvidencePage";
import { VerdictsPage } from "@/pages/VerdictsPage";
import { RunScanPage } from "@/pages/RunScanPage";
import { DeviceConsolePage } from "@/pages/DeviceConsolePage";
import { ControlsPage } from "@/pages/ControlsPage";
import { ControlDetailPage } from "@/pages/ControlDetailPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
        <Route path="/evidence" element={<EvidencePage />} />
        <Route path="/verdicts" element={<VerdictsPage />} />
        <Route path="/run-scan" element={<RunScanPage />} />
        <Route path="/console" element={<DeviceConsolePage />} />
        <Route path="/controls" element={<ControlsPage />} />
        <Route path="/controls/:controlId" element={<ControlDetailPage />} />
      </Routes>
    </BrowserRouter>
  );
}
