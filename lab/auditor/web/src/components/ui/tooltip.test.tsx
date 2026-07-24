import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Tooltip } from "./tooltip";

describe("Tooltip", () => {
  it("does not render its content until triggered", () => {
    render(
      <Tooltip content="Explains the button">
        <button type="button">Do the thing</button>
      </Tooltip>,
    );
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("shows the content on hover and hides it on mouse leave", async () => {
    const user = userEvent.setup();
    render(
      <Tooltip content="Explains the button">
        <button type="button">Do the thing</button>
      </Tooltip>,
    );
    const trigger = screen.getByRole("button", { name: "Do the thing" });

    await user.hover(trigger);
    expect(await screen.findByRole("tooltip")).toHaveTextContent("Explains the button");

    await user.unhover(trigger);
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });

  it("shows the content on keyboard focus and hides it on blur", async () => {
    const user = userEvent.setup();
    render(
      <Tooltip content="Explains the button">
        <button type="button">Do the thing</button>
      </Tooltip>,
    );

    await user.tab();
    expect(screen.getByRole("button", { name: "Do the thing" })).toHaveFocus();
    expect(await screen.findByRole("tooltip")).toHaveTextContent("Explains the button");

    await user.tab();
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
  });
});
