import { notFound, redirect as nextRedirect } from "next/navigation";

interface Demo { value?: string; }
interface UserProfile { email?: string; }

function useDemo(x?: Demo) {
  if (!x?.value) {
    return "nope";
  }
  return x.value.toUpperCase();
}

// Multiline default params should not be misread as global assignments.
const addDefaults = (
  a = 1,
  b = 2,
): number => a + b;

addDefaults();

type Session = { user: { email: string } } | null;

export function requireSession(session: Session): string {
  if (!session) {
    nextRedirect("/login");
  }

  return session.user.email.toLowerCase();
}

export function requireProfile(profile?: UserProfile): string {
  if (!profile) {
    notFound();
  }

  return profile.email ?? "anonymous@example.com";
}

// GH #76: `continue` ends the iteration, so the access below only runs when the
// guard did not fire.
export function collectEmails(profiles: (UserProfile | undefined)[]): string[] {
  const out: string[] = [];
  for (const profile of profiles) {
    if (!profile) continue;
    out.push(profile.email ?? "anonymous@example.com");
  }
  return out;
}

// GH #76: `break` leaves the loop entirely, same reasoning.
export function firstEmail(profiles: (UserProfile | undefined)[]): string {
  let found = "anonymous@example.com";
  for (const profile of profiles) {
    if (!profile) break;
    found = profile.email ?? found;
  }
  return found;
}
