import { useEffect, useState } from "react";

type Profile = {
  id: string;
  displayName: string;
};

async function fetchProfile(userId: string): Promise<Profile> {
  const response = await fetch(`/api/users/${encodeURIComponent(userId)}`);
  return response.json() as Promise<Profile>;
}

export function ProfilePanel({ userId }: { userId: string }) {
  const [profile, setProfile] = useState<Profile | null>(null);

  useEffect(async () => {
    const nextProfile = await fetchProfile(userId);
    setProfile(nextProfile);
  }, [userId]);

  return <h2>{profile?.displayName ?? "Loading"}</h2>;
}
