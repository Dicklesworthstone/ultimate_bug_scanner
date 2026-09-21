async function fetchUserProfile(id) {
  try {
    const resp = await fetch(`/api/users/${id}`, {
      signal: AbortSignal.timeout(5000),
    });
    return await resp.json();
  } catch (err) {
    console.error("Failed to load profile", err);
    throw err;
  } finally {
    console.log("profile fetch complete");
  }
}

async function saveSettings(settings) {
  try {
    await window.api.save(settings);
  } catch (err) {
    console.error("Save failed", err);
    throw err;
  } finally {
    console.log("settings sync complete");
  }
}

async function loadAllProjects(projectIds) {
  const projects = [];
  for (const id of projectIds) {
    try {
      const resp = await fetch(`/api/projects/${id}`, {
        signal: AbortSignal.timeout(5000),
      });
      projects.push(resp);
    } catch (err) {
      console.error("Project load failure", err);
      throw err;
    }
  }
  return projects;
}

export async function bootstrapSession(userId) {
  try {
    await fetchUserProfile(userId);
    await saveSettings({ theme: "dark" });
    await loadAllProjects([1, 2, 3]);
  } catch (err) {
    console.error("bootstrap failure", err);
    throw err;
  }
}
