import { jsx } from "react/jsx-runtime";
import { cn } from "./ui/utils";
function DashboardPanel({
  children,
  className
}) {
  return /* @__PURE__ */ jsx(
    "div",
    {
      className: cn("rounded-xl border bg-card", className),
      style: {
        borderColor: "#1e2738",
        backgroundColor: "#0f1420"
      },
      children
    }
  );
}
export {
  DashboardPanel
};
