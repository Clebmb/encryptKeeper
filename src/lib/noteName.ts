export function normalizeNoteName(name: string): string {
  const trimmed = name.trim().replaceAll("\\", "/");
  const withoutLeading = trimmed.replace(/^\/+/, "");
  if (!withoutLeading) {
    throw new Error("Note name cannot be empty.");
  }
  if (withoutLeading.includes("..")) {
    throw new Error("Parent directory segments are not allowed.");
  }
  return withoutLeading.endsWith(".gpg") ? withoutLeading : `${withoutLeading}.gpg`;
}
