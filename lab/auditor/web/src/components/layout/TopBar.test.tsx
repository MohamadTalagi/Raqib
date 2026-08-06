import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { TopBar } from "./TopBar";

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.removeAttribute("data-color-scheme");
});

afterEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
  document.documentElement.removeAttribute("data-color-scheme");
});

describe("TopBar theme toggle", () => {
  it("defaults to dark theme with no data-theme attribute set", () => {
    render(<TopBar title="Overview" />);
    expect(document.documentElement.getAttribute("data-theme")).toBeNull();
    expect(screen.getByRole("button", { name: /switch to light theme/i })).toBeInTheDocument();
  });

  it("switches to light theme on click, setting data-theme and persisting it", async () => {
    const user = userEvent.setup();
    render(<TopBar title="Overview" />);

    await user.click(screen.getByRole("button", { name: /switch to light theme/i }));

    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(localStorage.getItem("raqib-theme")).toBe("light");
    expect(screen.getByRole("button", { name: /switch to dark theme/i })).toBeInTheDocument();
  });

  it("switches back to dark on a second click", async () => {
    const user = userEvent.setup();
    render(<TopBar title="Overview" />);

    const button = () => screen.getByRole("button", { name: /switch to (light|dark) theme/i });
    await user.click(button());
    await user.click(button());

    expect(document.documentElement.getAttribute("data-theme")).toBeNull();
    expect(localStorage.getItem("raqib-theme")).toBe("dark");
  });

  it("reads a persisted light preference back on mount", () => {
    localStorage.setItem("raqib-theme", "light");
    render(<TopBar title="Overview" />);
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });
});

describe("TopBar color-scheme toggle", () => {
  it("defaults to the Default color scheme with no data-color-scheme attribute set", () => {
    render(<TopBar title="Overview" />);
    expect(document.documentElement.getAttribute("data-color-scheme")).toBeNull();
    expect(screen.getByRole("button", { name: /switch to kaustify color theme/i })).toBeInTheDocument();
  });

  it("switches to KAUSTify on click, setting data-color-scheme and persisting it", async () => {
    const user = userEvent.setup();
    render(<TopBar title="Overview" />);

    await user.click(screen.getByRole("button", { name: /switch to kaustify color theme/i }));

    expect(document.documentElement.getAttribute("data-color-scheme")).toBe("kaustify");
    expect(localStorage.getItem("raqib-color-scheme")).toBe("kaustify");
    expect(screen.getByRole("button", { name: /switch to default color theme/i })).toBeInTheDocument();
  });

  it("switches back to Default on a second click", async () => {
    const user = userEvent.setup();
    render(<TopBar title="Overview" />);

    const button = () => screen.getByRole("button", { name: /switch to (kaustify|default) color theme/i });
    await user.click(button());
    await user.click(button());

    expect(document.documentElement.getAttribute("data-color-scheme")).toBeNull();
    expect(localStorage.getItem("raqib-color-scheme")).toBe("default");
  });

  it("is independent of the dark/light toggle - switching one leaves the other untouched", async () => {
    const user = userEvent.setup();
    render(<TopBar title="Overview" />);

    await user.click(screen.getByRole("button", { name: /switch to kaustify color theme/i }));

    expect(document.documentElement.getAttribute("data-theme")).toBeNull();
    expect(document.documentElement.getAttribute("data-color-scheme")).toBe("kaustify");
  });
});
