import type {
  KeySummary,
  NoteEncryptionStatus,
  NoteSummary,
  OpenNoteResult,
  SessionStatus,
} from "../types";
import * as mockBackend from "./mockBackend";

const hasTauriRuntime =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function invokeOrMock<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!hasTauriRuntime) {
    switch (command) {
      case "get_status":
        return mockBackend.getStatus() as Promise<T>;
      case "open_folder_vault":
        return mockBackend.openFolderVault(
          String(args?.path ?? ""),
          Boolean(args?.recursive),
        ) as Promise<T>;
      case "list_notes":
        return mockBackend.listNotes() as Promise<T>;
      case "refresh_notes":
        return mockBackend.refreshNotes() as Promise<T>;
      case "open_note":
        return mockBackend.openNote(String(args?.noteId ?? args?.note_id ?? "")) as Promise<T>;
      case "save_note":
        return mockBackend.saveNote(
          String(args?.noteId ?? args?.note_id ?? ""),
          String(args?.content ?? ""),
        ) as Promise<T>;
      case "preview_pgp_block":
        return mockBackend.previewPgpBlock(String(args?.content ?? "")) as Promise<T>;
      case "inspect_note_encryption":
        return mockBackend.inspectNoteEncryption(
          String(args?.noteId ?? args?.note_id ?? ""),
        ) as Promise<T>;
      case "create_note":
        return mockBackend.createNote(
          String(args?.name ?? ""),
          String(args?.content ?? ""),
        ) as Promise<T>;
      case "rename_note":
        return mockBackend.renameNote(
          String(args?.noteId ?? args?.note_id ?? ""),
          String(args?.newName ?? args?.new_name ?? ""),
        ) as Promise<T>;
      case "delete_note":
        return mockBackend.deleteNote(String(args?.noteId ?? args?.note_id ?? "")) as Promise<T>;
      case "import_key_from_file":
        return mockBackend.importKey(String(args?.path ?? "")) as Promise<T>;
      case "import_key_from_text":
        return mockBackend.importKeyText(String(args?.armoredText ?? args?.armored_text ?? "")) as Promise<T>;
      case "create_key":
        return mockBackend.createKey(
          String(args?.name ?? ""),
          String(args?.email ?? ""),
          String(args?.passphrase ?? ""),
        ) as Promise<T>;
      case "list_keys":
        return mockBackend.listKeys() as Promise<T>;
      case "select_private_key":
        return mockBackend.selectPrivateKey(String(args?.fingerprint ?? "")) as Promise<T>;
      case "export_public_key":
        return mockBackend.exportPublicKey(
          String(args?.fingerprint ?? ""),
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "export_private_key":
        return mockBackend.exportPrivateKey(
          String(args?.fingerprint ?? ""),
          String(args?.passphrase ?? ""),
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "remove_key":
        return mockBackend.removeKey(String(args?.fingerprint ?? "")) as Promise<T>;
      case "set_recipients":
        return mockBackend.setRecipients((args?.fingerprints as string[]) ?? []) as Promise<T>;
      case "unlock_session":
        return mockBackend.unlockSession(String(args?.passphrase ?? "")) as Promise<T>;
      case "lock_session":
        return mockBackend.lockSession() as Promise<T>;
      case "update_preferences":
        return mockBackend.updatePreferences(
          Number(args?.recursiveScan ?? args?.recursive_scan ?? 0) === 1 ||
            Boolean(args?.recursiveScan ?? args?.recursive_scan),
          Number(args?.inactivityTimeoutSecs ?? args?.inactivity_timeout_secs ?? 900),
          Boolean(args?.autoSave ?? args?.auto_save),
        ) as Promise<T>;
      default:
        throw new Error(`Unsupported mock command: ${command}`);
    }
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke(command, args);
}

export async function getStatus(): Promise<SessionStatus> {
  return invokeOrMock("get_status");
}

export async function openFolderVault(path: string, recursive: boolean): Promise<NoteSummary[]> {
  return invokeOrMock("open_folder_vault", { path, recursive });
}

export async function listNotes(): Promise<NoteSummary[]> {
  return invokeOrMock("list_notes");
}

export async function refreshNotesFromVault(): Promise<NoteSummary[]> {
  return invokeOrMock("refresh_notes");
}

export async function openNote(noteId: string): Promise<OpenNoteResult> {
  return invokeOrMock("open_note", { noteId });
}

export async function saveNote(noteId: string, content: string): Promise<void> {
  return invokeOrMock("save_note", { noteId, content });
}

export async function previewPgpBlock(content: string): Promise<string> {
  return invokeOrMock("preview_pgp_block", { content });
}

export async function inspectNoteEncryption(noteId: string): Promise<NoteEncryptionStatus> {
  return invokeOrMock("inspect_note_encryption", { noteId });
}

export async function createNote(name: string, content: string): Promise<NoteSummary> {
  return invokeOrMock("create_note", { name, content });
}

export async function renameNote(noteId: string, newName: string): Promise<NoteSummary> {
  return invokeOrMock("rename_note", { noteId, newName });
}

export async function deleteNote(noteId: string): Promise<void> {
  return invokeOrMock("delete_note", { noteId });
}

export async function importKey(path: string): Promise<void> {
  return invokeOrMock("import_key_from_file", { path });
}

export async function importKeyText(armoredText: string): Promise<void> {
  return invokeOrMock("import_key_from_text", { armoredText });
}

export async function createKey(name: string, email: string, passphrase: string): Promise<void> {
  return invokeOrMock("create_key", { name, email, passphrase });
}

export async function listKeys(): Promise<KeySummary[]> {
  return invokeOrMock("list_keys");
}

export async function selectPrivateKey(fingerprint: string): Promise<void> {
  return invokeOrMock("select_private_key", { fingerprint });
}

export async function exportPublicKey(fingerprint: string, outputPath: string): Promise<void> {
  return invokeOrMock("export_public_key", { fingerprint, outputPath });
}

export async function exportPrivateKey(
  fingerprint: string,
  passphrase: string,
  outputPath: string,
): Promise<void> {
  return invokeOrMock("export_private_key", { fingerprint, passphrase, outputPath });
}

export async function removeKey(fingerprint: string, hasSecret: boolean): Promise<void> {
  return invokeOrMock("remove_key", { fingerprint, hasSecret });
}

export async function setRecipients(fingerprints: string[]): Promise<void> {
  return invokeOrMock("set_recipients", { fingerprints });
}

export async function unlockSession(passphrase: string): Promise<void> {
  return invokeOrMock("unlock_session", { passphrase });
}

export async function lockSession(): Promise<void> {
  return invokeOrMock("lock_session");
}

export async function updatePreferences(
  recursiveScan: boolean,
  inactivityTimeoutSecs: number,
  autoSave: boolean,
): Promise<SessionStatus> {
  return invokeOrMock("update_preferences", {
    recursiveScan,
    inactivityTimeoutSecs,
    autoSave,
  });
}

export function getBackendMode() {
  return hasTauriRuntime ? "tauri" : "mock";
}
