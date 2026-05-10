import type {
  ClipboardNoteContent,
  FileOperationResult,
  ImportKeyResult,
  KeyActionResult,
  KeyDetails,
  KeySummary,
  KeyserverSearchResult,
  NoteEncryptionStatus,
  NoteSignatureStatus,
  NoteSummary,
  OpenNoteResult,
  PinnedKeySettings,
  SmartcardStatus,
  X509CertificateSummary,
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
      case "open_archive_vault":
        return mockBackend.openArchiveVault(
          String(args?.path ?? ""),
          Boolean(args?.recursive),
        ) as Promise<T>;
      case "list_notes":
        return mockBackend.listNotes() as Promise<T>;
      case "refresh_notes":
        return mockBackend.refreshNotes() as Promise<T>;
      case "open_note":
        return mockBackend.openNote(String(args?.noteId ?? args?.note_id ?? "")) as Promise<T>;
      case "open_note_with_password":
        return mockBackend.openNoteWithPassword(
          String(args?.noteId ?? args?.note_id ?? ""),
          String(args?.password ?? ""),
        ) as Promise<T>;
      case "resolve_clipboard_note_content":
        return mockBackend.resolveClipboardNoteContent(
          String(args?.rawContent ?? args?.raw_content ?? ""),
        ) as Promise<T>;
      case "save_note":
        return mockBackend.saveNote(
          String(args?.noteId ?? args?.note_id ?? ""),
          String(args?.content ?? ""),
          Boolean(args?.useSignature ?? args?.use_signature),
        ) as Promise<T>;
      case "save_note_with_password":
        return mockBackend.saveNoteWithPassword(
          String(args?.noteId ?? args?.note_id ?? ""),
          String(args?.content ?? ""),
          String(args?.password ?? ""),
        ) as Promise<T>;
      case "preview_pgp_block":
        return mockBackend.previewPgpBlock(
          String(args?.content ?? ""),
          Boolean(args?.useSignature ?? args?.use_signature),
        ) as Promise<T>;
      case "verify_clipboard_signature":
        return mockBackend.verifyClipboardSignature(
          String(args?.signatureText ?? args?.signature_text ?? ""),
          String(args?.content ?? ""),
        ) as Promise<T>;
      case "inspect_note_encryption":
        return mockBackend.inspectNoteEncryption(
          String(args?.noteId ?? args?.note_id ?? ""),
        ) as Promise<T>;
      case "create_note":
        return mockBackend.createNote(
          String(args?.name ?? ""),
          String(args?.content ?? ""),
          Boolean(args?.useSignature ?? args?.use_signature),
        ) as Promise<T>;
      case "create_note_with_password":
        return mockBackend.createNoteWithPassword(
          String(args?.name ?? ""),
          String(args?.content ?? ""),
          String(args?.password ?? ""),
        ) as Promise<T>;
      case "rename_note":
        return mockBackend.renameNote(
          String(args?.noteId ?? args?.note_id ?? ""),
          String(args?.newName ?? args?.new_name ?? ""),
        ) as Promise<T>;
      case "delete_note":
        return mockBackend.deleteNote(String(args?.noteId ?? args?.note_id ?? "")) as Promise<T>;
      case "encrypt_files":
        return mockBackend.encryptFiles(
          (args?.inputPaths as string[] | undefined) ?? [],
          String(args?.outputDir ?? args?.output_dir ?? ""),
        ) as Promise<T>;
      case "decrypt_files":
        return mockBackend.decryptFiles(
          (args?.inputPaths as string[] | undefined) ?? [],
          String(args?.outputDir ?? args?.output_dir ?? ""),
        ) as Promise<T>;
      case "sign_files":
        return mockBackend.signFiles(
          (args?.inputPaths as string[] | undefined) ?? [],
          String(args?.outputDir ?? args?.output_dir ?? ""),
        ) as Promise<T>;
      case "encrypt_cms_files":
        return mockBackend.encryptCmsFiles(
          (args?.inputPaths as string[] | undefined) ?? [],
          String(args?.outputDir ?? args?.output_dir ?? ""),
          (args?.recipients as string[] | undefined) ?? [],
        ) as Promise<T>;
      case "decrypt_cms_files":
        return mockBackend.decryptCmsFiles(
          (args?.inputPaths as string[] | undefined) ?? [],
          String(args?.outputDir ?? args?.output_dir ?? ""),
        ) as Promise<T>;
      case "sign_cms_files":
        return mockBackend.signCmsFiles(
          (args?.inputPaths as string[] | undefined) ?? [],
          String(args?.outputDir ?? args?.output_dir ?? ""),
          String(args?.signer ?? ""),
        ) as Promise<T>;
      case "verify_file_signature":
        return mockBackend.verifyFileSignature(
          String(args?.inputPath ?? args?.input_path ?? ""),
          String(args?.signaturePath ?? args?.signature_path ?? ""),
        ) as Promise<T>;
      case "verify_cms_file_signature":
        return mockBackend.verifyCmsFileSignature(
          String(args?.inputPath ?? args?.input_path ?? ""),
          String(args?.signaturePath ?? args?.signature_path ?? ""),
        ) as Promise<T>;
      case "import_key_from_file":
        return mockBackend.importKey(String(args?.path ?? "")) as Promise<T>;
      case "import_key_from_text":
        return mockBackend.importKeyText(String(args?.armoredText ?? args?.armored_text ?? "")) as Promise<T>;
      case "lookup_key":
        return mockBackend.lookupKey(String(args?.query ?? "")) as Promise<T>;
      case "search_keyserver":
        return mockBackend.searchKeyserver(String(args?.query ?? "")) as Promise<T>;
      case "import_key_from_keyserver":
        return mockBackend.importKeyFromKeyserver(String(args?.fingerprint ?? "")) as Promise<T>;
      case "publish_key_to_keyserver":
        return mockBackend.publishKeyToKeyserver(String(args?.fingerprint ?? "")) as Promise<T>;
      case "refresh_key_from_keyserver":
        return mockBackend.refreshKeyFromKeyserver(String(args?.fingerprint ?? "")) as Promise<T>;
      case "refresh_all_keys_from_keyserver":
        return mockBackend.refreshAllKeysFromKeyserver() as Promise<T>;
      case "add_subkey":
        return mockBackend.addSubkey(
          String(args?.fingerprint ?? ""),
          String(args?.algorithm ?? ""),
          String(args?.usage ?? ""),
          String(args?.expire ?? ""),
        ) as Promise<T>;
      case "change_key_passphrase":
        return mockBackend.changeKeyPassphrase(
          String(args?.fingerprint ?? ""),
          String(args?.newPassphrase ?? args?.new_passphrase ?? ""),
        ) as Promise<T>;
      case "export_ownertrust":
        return mockBackend.exportOwnertrust(String(args?.outputPath ?? args?.output_path ?? "")) as Promise<T>;
      case "import_ownertrust":
        return mockBackend.importOwnertrust(String(args?.inputPath ?? args?.input_path ?? "")) as Promise<T>;
      case "create_key":
        return mockBackend.createKey(
          String(args?.name ?? ""),
          String(args?.email ?? ""),
          String(args?.passphrase ?? ""),
        ) as Promise<T>;
      case "list_keys":
        return mockBackend.listKeys() as Promise<T>;
      case "get_key_details":
        return mockBackend.getKeyDetails(String(args?.fingerprint ?? "")) as Promise<T>;
      case "get_smartcard_status":
        return mockBackend.getSmartcardStatus() as Promise<T>;
      case "list_x509_certificates":
        return mockBackend.listX509Certificates() as Promise<T>;
      case "learn_x509_card":
        return mockBackend.learnX509Card() as Promise<T>;
      case "create_x509_certificate":
        return mockBackend.createX509Certificate(
          String(args?.commonName ?? args?.common_name ?? ""),
          String(args?.organization ?? ""),
          String(args?.email ?? ""),
          String(args?.expiresAt ?? args?.expires_at ?? ""),
          String(args?.passphrase ?? ""),
        ) as Promise<T>;
      case "import_x509_certificate":
        return mockBackend.importX509Certificate(String(args?.path ?? "")) as Promise<T>;
      case "import_x509_certificate_text":
        return mockBackend.importX509CertificateText(
          String(args?.certificateText ?? args?.certificate_text ?? ""),
        ) as Promise<T>;
      case "export_x509_certificate":
        return mockBackend.exportX509Certificate(
          String(args?.fingerprint ?? ""),
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "export_x509_secret_key_p12":
        return mockBackend.exportX509SecretKeyP12(
          String(args?.fingerprint ?? ""),
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "export_x509_secret_key_p8":
        return mockBackend.exportX509SecretKeyP8(
          String(args?.fingerprint ?? ""),
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "change_x509_passphrase":
        return mockBackend.changeX509Passphrase(String(args?.fingerprint ?? "")) as Promise<T>;
      case "delete_x509_certificate":
        return mockBackend.deleteX509Certificate(String(args?.fingerprint ?? "")) as Promise<T>;
      case "get_x509_certificate_chain":
        return mockBackend.getX509CertificateChain(String(args?.fingerprint ?? "")) as Promise<T>;
      case "import_x509_crl":
        return mockBackend.importX509Crl(String(args?.path ?? "")) as Promise<T>;
      case "set_x509_trust_root":
        return mockBackend.setX509TrustRoot(
          String(args?.fingerprint ?? ""),
          Boolean(args?.trusted),
        ) as Promise<T>;
      case "export_x509_trustlist":
        return mockBackend.exportX509Trustlist(
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "import_x509_trustlist":
        return mockBackend.importX509Trustlist(
          String(args?.inputPath ?? args?.input_path ?? ""),
        ) as Promise<T>;
      case "restart_smartcard_service":
        return mockBackend.restartSmartcardService() as Promise<T>;
      case "change_smartcard_pin":
        return mockBackend.changeSmartcardPin() as Promise<T>;
      case "fetch_smartcard_public_key":
        return mockBackend.fetchSmartcardPublicKey() as Promise<T>;
      case "create_smartcard_key_stubs":
        return mockBackend.createSmartcardKeyStubs() as Promise<T>;
      case "generate_smartcard_key":
        return mockBackend.generateSmartcardKey(
          String(args?.slot ?? ""),
          String(args?.algorithm ?? ""),
          Boolean(args?.force),
        ) as Promise<T>;
      case "factory_reset_smartcard":
        return mockBackend.factoryResetSmartcard() as Promise<T>;
      case "move_secret_key_to_smartcard":
        return mockBackend.moveSecretKeyToSmartcard(
          String(args?.fingerprint ?? ""),
          String(args?.slot ?? ""),
          Boolean(args?.force),
        ) as Promise<T>;
      case "set_key_expiry":
        return mockBackend.setKeyExpiry(
          String(args?.fingerprint ?? ""),
          String(args?.expire ?? ""),
        ) as Promise<T>;
      case "set_key_ownertrust":
        return mockBackend.setKeyOwnertrust(
          String(args?.fingerprint ?? ""),
          String(args?.trust ?? ""),
        ) as Promise<T>;
      case "certify_key":
        return mockBackend.certifyKey(
          String(args?.fingerprint ?? ""),
          Boolean(args?.localOnly ?? args?.local_only),
        ) as Promise<T>;
      case "export_revocation_certificate":
        return mockBackend.exportRevocationCertificate(
          String(args?.fingerprint ?? ""),
          String(args?.passphrase ?? ""),
          String(args?.outputPath ?? args?.output_path ?? ""),
        ) as Promise<T>;
      case "get_pinned_key_settings":
        return mockBackend.getPinnedKeySettings() as Promise<T>;
      case "save_pinned_key_settings":
        return mockBackend.savePinnedKeySettings(
          (args?.privateKeyFingerprint as string | null | undefined) ?? null,
          (args?.recipientFingerprints as string[] | undefined) ?? [],
        ) as Promise<T>;
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

export async function openArchiveVault(path: string, recursive: boolean): Promise<NoteSummary[]> {
  return invokeOrMock("open_archive_vault", { path, recursive });
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

export async function openNoteWithPassword(noteId: string, password: string): Promise<OpenNoteResult> {
  return invokeOrMock("open_note_with_password", { noteId, password });
}

export async function resolveClipboardNoteContent(rawContent: string): Promise<ClipboardNoteContent> {
  return invokeOrMock("resolve_clipboard_note_content", { rawContent });
}

export async function saveNote(
  noteId: string,
  content: string,
  useSignature = false,
): Promise<void> {
  return invokeOrMock("save_note", { noteId, content, useSignature });
}

export async function saveNoteWithPassword(
  noteId: string,
  content: string,
  password: string,
): Promise<void> {
  return invokeOrMock("save_note_with_password", { noteId, content, password });
}

export async function previewPgpBlock(content: string, useSignature = false): Promise<string> {
  return invokeOrMock("preview_pgp_block", { content, useSignature });
}

export async function verifyClipboardSignature(
  signatureText: string,
  content: string,
): Promise<NoteSignatureStatus> {
  return invokeOrMock("verify_clipboard_signature", { signatureText, content });
}

export async function inspectNoteEncryption(noteId: string): Promise<NoteEncryptionStatus> {
  return invokeOrMock("inspect_note_encryption", { noteId });
}

export async function createNote(
  name: string,
  content: string,
  useSignature = false,
): Promise<NoteSummary> {
  return invokeOrMock("create_note", { name, content, useSignature });
}

export async function createNoteWithPassword(
  name: string,
  content: string,
  password: string,
): Promise<NoteSummary> {
  return invokeOrMock("create_note_with_password", { name, content, password });
}

export async function renameNote(noteId: string, newName: string): Promise<NoteSummary> {
  return invokeOrMock("rename_note", { noteId, newName });
}

export async function deleteNote(noteId: string): Promise<void> {
  return invokeOrMock("delete_note", { noteId });
}

export async function encryptFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  return invokeOrMock("encrypt_files", { inputPaths, outputDir });
}

export async function decryptFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  return invokeOrMock("decrypt_files", { inputPaths, outputDir });
}

export async function signFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  return invokeOrMock("sign_files", { inputPaths, outputDir });
}

export async function encryptCmsFiles(
  inputPaths: string[],
  outputDir: string,
  recipients: string[],
): Promise<FileOperationResult[]> {
  return invokeOrMock("encrypt_cms_files", { inputPaths, outputDir, recipients });
}

export async function decryptCmsFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  return invokeOrMock("decrypt_cms_files", { inputPaths, outputDir });
}

export async function signCmsFiles(
  inputPaths: string[],
  outputDir: string,
  signer: string,
): Promise<FileOperationResult[]> {
  return invokeOrMock("sign_cms_files", { inputPaths, outputDir, signer });
}

export async function verifyFileSignature(
  inputPath: string,
  signaturePath: string,
): Promise<NoteSignatureStatus> {
  return invokeOrMock("verify_file_signature", { inputPath, signaturePath });
}

export async function verifyCmsFileSignature(
  inputPath: string,
  signaturePath: string,
): Promise<NoteSignatureStatus> {
  return invokeOrMock("verify_cms_file_signature", { inputPath, signaturePath });
}

export async function importKey(path: string): Promise<ImportKeyResult> {
  return invokeOrMock("import_key_from_file", { path });
}

export async function importKeyText(armoredText: string): Promise<ImportKeyResult> {
  return invokeOrMock("import_key_from_text", { armoredText });
}

export async function lookupKey(query: string): Promise<ImportKeyResult> {
  return invokeOrMock("lookup_key", { query });
}

export async function searchKeyserver(query: string): Promise<KeyserverSearchResult[]> {
  return invokeOrMock("search_keyserver", { query });
}

export async function importKeyFromKeyserver(fingerprint: string): Promise<ImportKeyResult> {
  return invokeOrMock("import_key_from_keyserver", { fingerprint });
}

export async function publishKeyToKeyserver(fingerprint: string): Promise<KeyActionResult> {
  return invokeOrMock("publish_key_to_keyserver", { fingerprint });
}

export async function refreshKeyFromKeyserver(fingerprint: string): Promise<KeyActionResult> {
  return invokeOrMock("refresh_key_from_keyserver", { fingerprint });
}

export async function refreshAllKeysFromKeyserver(): Promise<KeyActionResult> {
  return invokeOrMock("refresh_all_keys_from_keyserver");
}

export async function addSubkey(
  fingerprint: string,
  algorithm: string,
  usage: string,
  expire: string,
): Promise<KeyActionResult> {
  return invokeOrMock("add_subkey", { fingerprint, algorithm, usage, expire });
}

export async function changeKeyPassphrase(
  fingerprint: string,
  newPassphrase: string,
): Promise<KeyActionResult> {
  return invokeOrMock("change_key_passphrase", { fingerprint, newPassphrase });
}

export async function exportOwnertrust(outputPath: string): Promise<KeyActionResult> {
  return invokeOrMock("export_ownertrust", { outputPath });
}

export async function importOwnertrust(inputPath: string): Promise<KeyActionResult> {
  return invokeOrMock("import_ownertrust", { inputPath });
}

export async function createKey(name: string, email: string, passphrase: string): Promise<void> {
  return invokeOrMock("create_key", { name, email, passphrase });
}

export async function listKeys(): Promise<KeySummary[]> {
  return invokeOrMock("list_keys");
}

export async function getKeyDetails(fingerprint: string): Promise<KeyDetails> {
  return invokeOrMock("get_key_details", { fingerprint });
}

export async function getSmartcardStatus(): Promise<SmartcardStatus> {
  return invokeOrMock("get_smartcard_status");
}

export async function listX509Certificates(): Promise<X509CertificateSummary[]> {
  return invokeOrMock("list_x509_certificates");
}

export async function learnX509Card(): Promise<KeyActionResult> {
  return invokeOrMock("learn_x509_card");
}

export async function createX509Certificate(
  commonName: string,
  organization: string,
  email: string,
  expiresAt: string,
  passphrase: string,
): Promise<KeyActionResult> {
  return invokeOrMock("create_x509_certificate", {
    commonName,
    organization,
    email,
    expiresAt,
    passphrase,
  });
}

export async function importX509Certificate(path: string): Promise<KeyActionResult> {
  return invokeOrMock("import_x509_certificate", { path });
}

export async function importX509CertificateText(certificateText: string): Promise<KeyActionResult> {
  return invokeOrMock("import_x509_certificate_text", { certificateText });
}

export async function exportX509Certificate(
  fingerprint: string,
  outputPath: string,
): Promise<KeyActionResult> {
  return invokeOrMock("export_x509_certificate", { fingerprint, outputPath });
}

export async function exportX509SecretKeyP12(
  fingerprint: string,
  outputPath: string,
): Promise<KeyActionResult> {
  return invokeOrMock("export_x509_secret_key_p12", { fingerprint, outputPath });
}

export async function exportX509SecretKeyP8(
  fingerprint: string,
  outputPath: string,
): Promise<KeyActionResult> {
  return invokeOrMock("export_x509_secret_key_p8", { fingerprint, outputPath });
}

export async function changeX509Passphrase(fingerprint: string): Promise<KeyActionResult> {
  return invokeOrMock("change_x509_passphrase", { fingerprint });
}

export async function deleteX509Certificate(fingerprint: string): Promise<KeyActionResult> {
  return invokeOrMock("delete_x509_certificate", { fingerprint });
}

export async function getX509CertificateChain(fingerprint: string): Promise<string> {
  return invokeOrMock("get_x509_certificate_chain", { fingerprint });
}

export async function importX509Crl(path: string): Promise<KeyActionResult> {
  return invokeOrMock("import_x509_crl", { path });
}

export async function setX509TrustRoot(
  fingerprint: string,
  trusted: boolean,
): Promise<KeyActionResult> {
  return invokeOrMock("set_x509_trust_root", { fingerprint, trusted });
}

export async function exportX509Trustlist(outputPath: string): Promise<KeyActionResult> {
  return invokeOrMock("export_x509_trustlist", { outputPath });
}

export async function importX509Trustlist(inputPath: string): Promise<KeyActionResult> {
  return invokeOrMock("import_x509_trustlist", { inputPath });
}

export async function restartSmartcardService(): Promise<KeyActionResult> {
  return invokeOrMock("restart_smartcard_service");
}

export async function changeSmartcardPin(): Promise<KeyActionResult> {
  return invokeOrMock("change_smartcard_pin");
}

export async function fetchSmartcardPublicKey(): Promise<KeyActionResult> {
  return invokeOrMock("fetch_smartcard_public_key");
}

export async function createSmartcardKeyStubs(): Promise<KeyActionResult> {
  return invokeOrMock("create_smartcard_key_stubs");
}

export async function generateSmartcardKey(
  slot: string,
  algorithm: string,
  force: boolean,
): Promise<KeyActionResult> {
  return invokeOrMock("generate_smartcard_key", { slot, algorithm, force });
}

export async function factoryResetSmartcard(): Promise<KeyActionResult> {
  return invokeOrMock("factory_reset_smartcard");
}

export async function moveSecretKeyToSmartcard(
  fingerprint: string,
  slot: string,
  force: boolean,
): Promise<KeyActionResult> {
  return invokeOrMock("move_secret_key_to_smartcard", { fingerprint, slot, force });
}

export async function setKeyExpiry(
  fingerprint: string,
  expire: string,
): Promise<KeyActionResult> {
  return invokeOrMock("set_key_expiry", { fingerprint, expire });
}

export async function setKeyOwnertrust(
  fingerprint: string,
  trust: string,
): Promise<KeyActionResult> {
  return invokeOrMock("set_key_ownertrust", { fingerprint, trust });
}

export async function certifyKey(
  fingerprint: string,
  localOnly: boolean,
): Promise<KeyActionResult> {
  return invokeOrMock("certify_key", { fingerprint, localOnly });
}

export async function exportRevocationCertificate(
  fingerprint: string,
  passphrase: string,
  outputPath: string,
): Promise<KeyActionResult> {
  return invokeOrMock("export_revocation_certificate", {
    fingerprint,
    passphrase,
    outputPath,
  });
}

export async function getPinnedKeySettings(): Promise<PinnedKeySettings> {
  return invokeOrMock("get_pinned_key_settings");
}

export async function savePinnedKeySettings(
  privateKeyFingerprint: string | null,
  recipientFingerprints: string[],
): Promise<PinnedKeySettings> {
  return invokeOrMock("save_pinned_key_settings", {
    privateKeyFingerprint,
    recipientFingerprints,
  });
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
