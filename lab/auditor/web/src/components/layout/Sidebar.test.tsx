import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Sidebar } from "./Sidebar";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Sidebar open onClose={() => {}} />
    </MemoryRouter>,
  );
}

describe("Sidebar Home/Overview nav", () => {
  it("has Home above Overview, Home at / and Overview at /overview", () => {
    renderAt("/");
    const home = screen.getByRole("link", { name: /^home$/i });
    const overview = screen.getByRole("link", { name: /^overview$/i });
    expect(home).toHaveAttribute("href", "/");
    expect(overview).toHaveAttribute("href", "/overview");
    // Home comes first in document order.
    expect(home.compareDocumentPosition(overview) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("highlights only Home at /, and only Overview at /overview", () => {
    const first = renderAt("/");
    expect(screen.getByRole("link", { name: /^home$/i })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /^overview$/i })).not.toHaveAttribute("aria-current");
    first.unmount();

    renderAt("/overview");
    expect(screen.getByRole("link", { name: /^overview$/i })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /^home$/i })).not.toHaveAttribute("aria-current");
  });
});

describe("Sidebar active state", () => {
  it("highlights only NCA Compliance on the NCA Compliance page itself", () => {
    renderAt("/nca-compliance");
    expect(screen.getAllByRole("link", { current: "page" })).toHaveLength(1);
    expect(screen.getByRole("link", { name: /nca compliance/i })).toHaveAttribute("aria-current", "page");
  });

  it("highlights only NCA Controls on the controls catalog, not NCA Compliance too", () => {
    // Regression: "NCA Compliance" used to link to /nca-compliance with
    // NavLink's `end` unset (defaulting to a prefix match), so any sub-route
    // - including /nca-compliance/controls, which has its own nav item -
    // lit up both links at once.
    renderAt("/nca-compliance/controls");
    const activeLinks = screen.getAllByRole("link", { current: "page" });
    expect(activeLinks).toHaveLength(1);
    expect(activeLinks[0]).toHaveAccessibleName(/nca controls/i);
  });

  it("highlights only NCA Controls on a control detail page", () => {
    renderAt("/nca-compliance/controls/NCA-CGIoT-1_2024-2-2-2");
    const activeLinks = screen.getAllByRole("link", { current: "page" });
    expect(activeLinks).toHaveLength(1);
    expect(activeLinks[0]).toHaveAccessibleName(/nca controls/i);
  });

  it("links to Organizational Compliance, and highlights only that link there", () => {
    // Previously only reachable via an inline text link inside the NCA
    // Compliance page's disclaimer banner - no sidebar entry at all.
    renderAt("/nca-compliance/organization");
    expect(screen.getByRole("link", { name: /organizational compliance/i })).toHaveAttribute(
      "href",
      "/nca-compliance/organization",
    );
    const activeLinks = screen.getAllByRole("link", { current: "page" });
    expect(activeLinks).toHaveLength(1);
    expect(activeLinks[0]).toHaveAccessibleName(/organizational compliance/i);
  });
});
