type ReportLink = {
  href: string;
  label: string;
};

export function ReportLinks({ links }: { links: ReportLink[] }) {
  return (
    <nav>
      {links.map((link) => (
        <a href={link.href} target="_blank" key={link.href}>
          {link.label}
        </a>
      ))}
    </nav>
  );
}
