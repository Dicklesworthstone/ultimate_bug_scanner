async function fetchUserProfile(id) {
  const resp = await fetch(`/api/users/${id}`);
  const json = await resp.json();
  return json.displayName;
}

function saveSettings(settings) {
  return window.api.save(settings).then(() => console.log("saved!"));
}

async function loadAllProjects(projectIds) {
  const results = await Promise.all(projectIds.map((id) => fetch(`/api/projects/${id}`)));
  return results;
}

export async function bootstrapSession(userId) {
  await fetchUserProfile(userId);
  saveSettings({ theme: "dark" });
  await loadAllProjects([1, 2, 3]);
}
