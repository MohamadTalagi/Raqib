import { BrowserRouter, Routes, Route } from "react-router-dom";
import { OverviewPage } from "@/pages/OverviewPage";
import { DevicesPage } from "@/pages/DevicesPage";
import { EvidencePage } from "@/pages/EvidencePage";
import { VerdictsPage } from "@/pages/VerdictsPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/evidence" element={<EvidencePage />} />
        <Route path="/verdicts" element={<VerdictsPage />} />
      </Routes>
    </BrowserRouter>
  );
}
