type ReportLink = {
  href: string;
  label: string;
};

export function openReport(link: ReportLink): void {
  window.open(link.href, "_blank");
}

openReport({ href: "https://reports.example.test/monthly", label: "Monthly report" });
