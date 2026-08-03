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
// guard did not fire. Keep the body longer than the text heuristic's lookahead
// window so the fixture exercises the guard line itself, not a nearby `return`.
export function collectEmails(profiles: (UserProfile | undefined)[]): string[] {
  const out: string[] = [];
  let skipped = 0;
  for (const profile of profiles) {
    if (!profile) continue;
    out.push(profile.email ?? "anonymous@example.com");
    console.debug("collected", out.length);
    console.debug("skipped so far", skipped);
    skipped += 0;
    console.debug("still going");
    console.debug("done with entry");
  }
  return out;
}

// GH #76: `break` leaves the loop entirely, same reasoning.
export function firstEmail(profiles: (UserProfile | undefined)[]): string {
  let found = "anonymous@example.com";
  let visited = 0;
  for (const profile of profiles) {
    if (!profile) break;
    found = profile.email ?? found;
    console.debug("visiting", visited);
    visited += 1;
    console.debug("current", found);
    console.debug("still going");
    console.debug("done with entry");
  }
  return found;
}
