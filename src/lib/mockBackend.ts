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
import { normalizeNoteName } from "./noteName";

interface MockNoteRecord extends NoteSummary {
  content: string;
}

interface MockStore {
  status: SessionStatus;
  keys: KeySummary[];
  notes: MockNoteRecord[];
}

const STORAGE_KEY = "encryptkeeper.mock.store";
const PINNED_SETTINGS_STORAGE_KEY = "encryptkeeper.mock.pinned-key-settings";

const defaultStatus: SessionStatus = {
  vault_kind: "none",
  vault_path: null,
  archive_unlocked: false,
  session_unlocked: false,
  selected_private_key: null,
  selected_recipients: [],
  inactivity_timeout_secs: 0,
  remaining_auto_lock_secs: null,
  recursive_scan: true,
  auto_save: false,
};

const demoKeys: KeySummary[] = [
  {
    key_id: "DEMO-PRIVATE-KEY-001",
    fingerprint: "DEMO-PRIVATE-KEY-001",
    user_ids: ["Demo User <demo@encryptkeeper.local>"],
    has_secret: true,
    algorithm: "RSA",
    bits: 3072,
    created_at: 1712707200,
    expires_at: null,
    trust: "Ultimate",
    capabilities: ["Sign", "Encrypt", "Certify"],
    is_selected_private: false,
    is_selected_recipient: false,
  },
  {
    key_id: "DEMO-PUBLIC-KEY-002",
    fingerprint: "DEMO-PUBLIC-KEY-002",
    user_ids: ["Team Recipient <team@encryptkeeper.local>"],
    has_secret: false,
    algorithm: "RSA",
    bits: 3072,
    created_at: 1712707200,
    expires_at: null,
    trust: "Full",
    capabilities: ["Encrypt"],
    is_selected_private: false,
    is_selected_recipient: false,
  },
];

const demoNotes: MockNoteRecord[] = [
  {
    id: crypto.randomUUID(),
    name: "welcome.gpg",
    relative_path: "welcome.gpg",
    content: "# encryptKeeper\n\nThis is browser mock mode. No real encryption is happening here.",
  },
  {
    id: crypto.randomUUID(),
    name: "ideas.gpg",
    relative_path: "ideas.gpg",
    content: "- Add ZIP vault support\n- Integrate real gpg-agent reuse\n- Upgrade editor to CodeMirror",
  },
];

function loadStore(): MockStore {
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    const store: MockStore = {
      status: defaultStatus,
      keys: demoKeys,
      notes: demoNotes,
    };
    saveStore(store);
    return store;
  }
  return JSON.parse(raw) as MockStore;
}

function saveStore(store: MockStore) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

function lastPathSegment(value: string) {
  const segments = value.split("/");
  return segments[segments.length - 1] ?? value;
}

function applySelectionFlags(store: MockStore): MockStore {
  return {
    ...store,
    keys: store.keys.map((key) => ({
      ...key,
      is_selected_private: key.fingerprint === store.status.selected_private_key,
      is_selected_recipient: store.status.selected_recipients.includes(key.fingerprint),
    })),
  };
}

function getStore(): MockStore {
  return applySelectionFlags(loadStore());
}

function updateStore(mutator: (store: MockStore) => MockStore): MockStore {
  const next = applySelectionFlags(mutator(loadStore()));
  saveStore(next);
  return next;
}

function mockSignature(store: MockStore): NoteSignatureStatus {
  return {
    state: store.status.selected_private_key ? "good" : "unknown",
    signer_key_id: store.status.selected_private_key?.slice(-16) ?? null,
    signer_fingerprint: store.status.selected_private_key,
    signer_label:
      store.keys.find((key) => key.fingerprint === store.status.selected_private_key)?.user_ids[0] ??
      null,
    summary: store.status.selected_private_key
      ? "Good signature from the selected mock private key."
      : "Unlock the session to verify this note's signature.",
  };
}

export async function getStatus(): Promise<SessionStatus> {
  return getStore().status;
}

export async function openFolderVault(path: string, recursive: boolean): Promise<NoteSummary[]> {
  const store = updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      vault_kind: "folder",
      vault_path: path,
      archive_unlocked: false,
      recursive_scan: recursive,
    },
  }));
  return store.notes;
}

export async function openArchiveVault(path: string, recursive: boolean): Promise<NoteSummary[]> {
  const store = updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      vault_kind: "archive",
      vault_path: path,
      archive_unlocked: true,
      recursive_scan: recursive,
    },
  }));
  return store.notes;
}

export async function listNotes(): Promise<NoteSummary[]> {
  return getStore().notes;
}

export async function refreshNotes(): Promise<NoteSummary[]> {
  return getStore().notes;
}

export async function openNote(noteId: string): Promise<OpenNoteResult> {
  const store = getStore();
  if (!store.status.session_unlocked) {
    throw new Error("Session is locked. Unlock the mock session first.");
  }
  const note = store.notes.find((entry) => entry.id === noteId);
  if (!note) {
    throw new Error("Note not found.");
  }
  return {
    note,
    content: note.content,
  };
}

export async function openNoteWithPassword(noteId: string, password: string): Promise<OpenNoteResult> {
  if (!password) {
    throw new Error("Enter a password.");
  }
  const store = getStore();
  const note = store.notes.find((entry) => entry.id === noteId);
  if (!note) {
    throw new Error("Note not found.");
  }
  return {
    note,
    content: note.content,
  };
}

export async function resolveClipboardNoteContent(
  rawContent: string,
): Promise<ClipboardNoteContent> {
  const store = getStore();
  if (
    rawContent.includes("-----BEGIN PGP SIGNED MESSAGE-----") &&
    rawContent.includes("-----BEGIN PGP SIGNATURE-----")
  ) {
    const content = rawContent
      .split(/\r?\n/)
      .filter(
        (line) =>
          !line.startsWith("-----BEGIN PGP") &&
          !line.startsWith("-----END PGP") &&
          !line.startsWith("Hash:") &&
          !line.startsWith("Version:") &&
          !line.includes(":"),
      )
      .join("\n")
      .trim();
    return {
      content: content || rawContent,
      was_decrypted: true,
      signature: mockSignature(store),
    };
  }

  if (
    store.status.session_unlocked &&
    store.status.selected_private_key &&
    rawContent.includes("-----BEGIN PGP MESSAGE-----") &&
    rawContent.includes("-----END PGP MESSAGE-----")
  ) {
    const lines = rawContent
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const body = lines.filter(
      (line) =>
        !line.startsWith("-----BEGIN PGP MESSAGE-----") &&
        !line.startsWith("-----END PGP MESSAGE-----") &&
        !line.startsWith("Version:"),
    );
    if (body.length > 0) {
      try {
        const decoded = decodeURIComponent(escape(atob(body.join(""))));
        return {
          content: decoded,
          was_decrypted: true,
          signature: {
            ...mockSignature(store),
          },
        };
      } catch {
        return { content: rawContent, was_decrypted: false, signature: null };
      }
    }
  }

  return { content: rawContent, was_decrypted: false, signature: null };
}

export async function saveNote(
  noteId: string,
  content: string,
  _useSignature = false,
): Promise<void> {
  updateStore((current) => ({
    ...current,
    notes: current.notes.map((note) => (note.id === noteId ? { ...note, content } : note)),
  }));
}

export async function saveNoteWithPassword(
  noteId: string,
  content: string,
  password: string,
): Promise<void> {
  if (!password) {
    throw new Error("Enter a password.");
  }
  await saveNote(noteId, content);
}

export async function previewPgpBlock(content: string, useSignature = false): Promise<string> {
  const store = getStore();
  if (!store.status.session_unlocked) {
    throw new Error("Session is locked. Unlock the mock session first.");
  }
  if (!store.status.selected_private_key) {
    throw new Error("Select a private key first.");
  }
  if (useSignature || store.status.selected_recipients.length === 0) {
    return [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      content || "",
      "-----BEGIN PGP SIGNATURE-----",
      "",
      "mock-signature",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
  }
  if (store.status.selected_recipients.length === 0) {
    throw new Error("Select at least one recipient first.");
  }

  const body = btoa(unescape(encodeURIComponent(content || ""))).replace(/(.{64})/g, "$1\n");
  return [
    "-----BEGIN PGP MESSAGE-----",
    "",
    "Version: encryptKeeper mock",
    "",
    body || "=",
    "-----END PGP MESSAGE-----",
  ].join("\n");
}

export async function verifyClipboardSignature(
  signatureText: string,
  _content: string,
): Promise<NoteSignatureStatus> {
  if (!signatureText.includes("BEGIN PGP SIGNATURE")) {
    throw new Error("Clipboard does not contain a PGP signature.");
  }
  return mockSignature(getStore());
}

export async function inspectNoteEncryption(_noteId: string): Promise<NoteEncryptionStatus> {
  const store = getStore();
  const recipients = store.status.selected_recipients.map((fingerprint) => {
    const key = store.keys.find((entry) => entry.fingerprint === fingerprint);
    return {
      key_id: fingerprint.slice(-16),
      fingerprint,
      label: key?.user_ids[0] ?? fingerprint,
      has_secret: Boolean(key?.has_secret),
      is_selected_private: store.status.selected_private_key === fingerprint,
      is_selected_recipient: true,
    };
  });

  return {
    recipients,
    can_decrypt_with_selected_key: recipients.some(
      (recipient) => recipient.fingerprint === store.status.selected_private_key,
    ),
    matches_selected_recipients: true,
    signature: mockSignature(store),
  };
}

export async function createNote(
  name: string,
  content: string,
  _useSignature = false,
): Promise<NoteSummary> {
  const normalized = normalizeNoteName(name);
  const created: MockNoteRecord = {
    id: crypto.randomUUID(),
    name: lastPathSegment(normalized),
    relative_path: normalized,
    content,
  };
  updateStore((current) => ({
    ...current,
    notes: [...current.notes, created].sort((left, right) =>
      left.relative_path.localeCompare(right.relative_path),
    ),
  }));
  return created;
}

export async function createNoteWithPassword(
  name: string,
  content: string,
  password: string,
): Promise<NoteSummary> {
  if (!password) {
    throw new Error("Enter a password.");
  }
  return createNote(name, content);
}

export async function renameNote(noteId: string, newName: string): Promise<NoteSummary> {
  const normalized = normalizeNoteName(newName);
  let renamed: MockNoteRecord | undefined;
  updateStore((current) => ({
    ...current,
    notes: current.notes.map((note) => {
      if (note.id !== noteId) {
        return note;
      }
      renamed = {
        ...note,
        name: lastPathSegment(normalized),
        relative_path: normalized,
      };
      return renamed;
    }),
  }));
  if (!renamed) {
    throw new Error("Note not found.");
  }
  return renamed;
}

export async function deleteNote(noteId: string): Promise<void> {
  updateStore((current) => ({
    ...current,
    notes: current.notes.filter((note) => note.id !== noteId),
  }));
}

export async function encryptFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  if (inputPaths.length === 0 || !outputDir) {
    throw new Error("Choose files and an output folder.");
  }
  return inputPaths.map((inputPath) => ({
    input_path: inputPath,
    output_path: `${outputDir}/${lastPathSegment(inputPath)}.gpg`,
    operation: "encrypt",
  }));
}

export async function decryptFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  if (inputPaths.length === 0 || !outputDir) {
    throw new Error("Choose files and an output folder.");
  }
  return inputPaths.map((inputPath) => ({
    input_path: inputPath,
    output_path: `${outputDir}/${lastPathSegment(inputPath).replace(/\.gpg$/i, "") || `${lastPathSegment(inputPath)}.decrypted`}`,
    operation: "decrypt",
  }));
}

export async function signFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  if (inputPaths.length === 0 || !outputDir) {
    throw new Error("Choose files and an output folder.");
  }
  return inputPaths.map((inputPath) => ({
    input_path: inputPath,
    output_path: `${outputDir}/${lastPathSegment(inputPath)}.sig`,
    operation: "sign",
  }));
}

export async function encryptCmsFiles(
  inputPaths: string[],
  outputDir: string,
  recipients: string[],
): Promise<FileOperationResult[]> {
  if (inputPaths.length === 0 || !outputDir || recipients.length === 0) {
    throw new Error("Choose files, an output folder, and at least one X.509 recipient.");
  }
  return inputPaths.map((inputPath) => ({
    input_path: inputPath,
    output_path: `${outputDir}/${lastPathSegment(inputPath)}.p7m`,
    operation: "encrypt-cms",
  }));
}

export async function decryptCmsFiles(
  inputPaths: string[],
  outputDir: string,
): Promise<FileOperationResult[]> {
  if (inputPaths.length === 0 || !outputDir) {
    throw new Error("Choose files and an output folder.");
  }
  return inputPaths.map((inputPath) => ({
    input_path: inputPath,
    output_path: `${outputDir}/${lastPathSegment(inputPath).replace(/\.p7m$/i, "") || `${lastPathSegment(inputPath)}.decrypted`}`,
    operation: "decrypt-cms",
  }));
}

export async function signCmsFiles(
  inputPaths: string[],
  outputDir: string,
  signer: string,
): Promise<FileOperationResult[]> {
  if (inputPaths.length === 0 || !outputDir || !signer) {
    throw new Error("Choose files, an output folder, and an X.509 signing certificate.");
  }
  return inputPaths.map((inputPath) => ({
    input_path: inputPath,
    output_path: `${outputDir}/${lastPathSegment(inputPath)}.p7s`,
    operation: "sign-cms",
  }));
}

export async function verifyFileSignature(
  inputPath: string,
  signaturePath: string,
): Promise<NoteSignatureStatus> {
  if (!inputPath || !signaturePath) {
    throw new Error("Choose a file and detached signature.");
  }
  return mockSignature(getStore());
}

export async function verifyCmsFileSignature(
  inputPath: string,
  signaturePath: string,
): Promise<NoteSignatureStatus> {
  if (!inputPath || !signaturePath) {
    throw new Error("Choose a file and a CMS signature.");
  }
  return {
    state: "good",
    signer_key_id: null,
    signer_fingerprint: null,
    signer_label: "Demo X.509 signer",
    summary: "CMS signature verified.",
  };
}

export async function importKey(path: string): Promise<ImportKeyResult> {
  const pathSegments = path.split(/[/\\]/);
  const name = pathSegments[pathSegments.length - 1] ?? "Imported Key";
  const fingerprint = `IMPORTED-${name}-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();
  updateStore((current) => ({
    ...current,
    keys: [
      ...current.keys,
      {
        key_id: fingerprint.slice(-16),
        fingerprint,
        user_ids: [`${name} <imported@encryptkeeper.local>`],
        has_secret: true,
        algorithm: "RSA",
        bits: 3072,
        created_at: 1712707200,
        expires_at: null,
        trust: "Unknown",
        capabilities: ["Sign", "Encrypt"],
        is_selected_private: false,
        is_selected_recipient: false,
        },
      ],
  }));
  return {
    imported: 1,
    unchanged: 0,
    secret_imported: 1,
    fingerprints: [fingerprint],
    imported_fingerprints: [fingerprint],
    unchanged_fingerprints: [],
    summary: "Imported 1 key(s), 1 secret key(s).",
  };
}

export async function importKeyText(armoredText: string): Promise<ImportKeyResult> {
  if (!armoredText.includes("BEGIN PGP")) {
    throw new Error("Clipboard does not contain a PGP key block.");
  }

  const fingerprint = `CLIPBOARD-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();
  const hasSecret = armoredText.includes("PRIVATE KEY");
  updateStore((current) => ({
    ...current,
    keys: [
      ...current.keys,
      {
        key_id: fingerprint.slice(-16),
        fingerprint,
        user_ids: [`Clipboard Import <imported@encryptkeeper.local>`],
        has_secret: hasSecret,
        algorithm: "RSA",
        bits: 3072,
        created_at: 1712707200,
        expires_at: null,
        trust: hasSecret ? "Ultimate" : "Unknown",
        capabilities: hasSecret ? ["Sign", "Encrypt"] : ["Encrypt"],
        is_selected_private: false,
        is_selected_recipient: false,
        },
      ],
  }));
  return {
    imported: 1,
    unchanged: 0,
    secret_imported: hasSecret ? 1 : 0,
    fingerprints: [fingerprint],
    imported_fingerprints: [fingerprint],
    unchanged_fingerprints: [],
    summary: hasSecret
      ? "Imported 1 key(s), 1 secret key(s)."
      : "Imported 1 key(s).",
  };
}

export async function lookupKey(query: string): Promise<ImportKeyResult> {
  const trimmed = query.trim();
  if (!trimmed) {
    throw new Error("Lookup query is required.");
  }

  const fingerprint = `LOOKUP-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();
  updateStore((current) => ({
    ...current,
    keys: [
      ...current.keys,
      {
        key_id: fingerprint.slice(-16),
        fingerprint,
        user_ids: [`${trimmed} <lookup@encryptkeeper.local>`],
        has_secret: false,
        algorithm: "RSA",
        bits: 3072,
        created_at: 1712707200,
        expires_at: null,
        trust: "Unknown",
        capabilities: ["Encrypt"],
        is_selected_private: false,
        is_selected_recipient: false,
      },
    ],
  }));

  return {
    imported: 1,
    unchanged: 0,
    secret_imported: 0,
    fingerprints: [fingerprint],
    imported_fingerprints: [fingerprint],
    unchanged_fingerprints: [],
    summary: `Lookup completed for ${trimmed}. Imported 1 key(s).`,
  };
}

export async function searchKeyserver(query: string): Promise<KeyserverSearchResult[]> {
  const trimmed = query.trim();
  if (!trimmed) {
    throw new Error("Search query is required.");
  }

  return [
    {
      fingerprint: "MOCKSEARCH1234567890ABCDEF1234567890ABCDEF",
      algorithm: "EdDSA",
      bits: 256,
      created_at: 1712707200,
      user_ids: [`${trimmed} <lookup@encryptkeeper.local>`],
    },
  ];
}

export async function importKeyFromKeyserver(fingerprint: string): Promise<ImportKeyResult> {
  return lookupKey(fingerprint);
}

export async function publishKeyToKeyserver(fingerprint: string): Promise<KeyActionResult> {
  return {
    fingerprint,
    summary: `Published ${fingerprint} to the public keyserver.`,
  };
}

export async function refreshKeyFromKeyserver(fingerprint: string): Promise<KeyActionResult> {
  return {
    fingerprint,
    summary: `Refreshed from keyserver. Imported 1 key(s).`,
  };
}

export async function refreshAllKeysFromKeyserver(): Promise<KeyActionResult> {
  return {
    fingerprint: "all",
    summary: "Refreshed keyring from keyserver.",
  };
}

export async function addSubkey(
  fingerprint: string,
  _algorithm: string,
  usage: string,
  _expire: string,
): Promise<KeyActionResult> {
  const store = getStore();
  if (!store.status.session_unlocked) {
    throw new Error("Unlock the session before adding subkeys.");
  }
  const key = store.keys.find((entry) => entry.fingerprint === fingerprint);
  if (!key) {
    throw new Error("Key not found.");
  }
  return {
    fingerprint,
    summary: `Added a ${usage} subkey to ${fingerprint}.`,
  };
}

export async function changeKeyPassphrase(
  fingerprint: string,
  newPassphrase: string,
): Promise<KeyActionResult> {
  const store = getStore();
  if (!store.status.session_unlocked) {
    throw new Error("Unlock the session before changing the key passphrase.");
  }
  if (store.status.selected_private_key !== fingerprint) {
    throw new Error("Select and unlock this private key before changing its passphrase.");
  }
  if (!newPassphrase) {
    throw new Error("Enter a new key passphrase.");
  }
  return {
    fingerprint,
    summary: `Updated passphrase for ${fingerprint}.`,
  };
}

export async function exportOwnertrust(outputPath: string): Promise<KeyActionResult> {
  if (!outputPath) {
    throw new Error("Choose an output file.");
  }
  return {
    fingerprint: "ownertrust",
    summary: `Exported ownertrust to ${outputPath}.`,
  };
}

export async function importOwnertrust(inputPath: string): Promise<KeyActionResult> {
  if (!inputPath) {
    throw new Error("Choose an ownertrust file.");
  }
  return {
    fingerprint: "ownertrust",
    summary: `Imported ownertrust from ${inputPath}.`,
  };
}

export async function createKey(name: string, email: string, _passphrase: string): Promise<void> {
  const trimmedName = name.trim();
  const trimmedEmail = email.trim();
  if (!trimmedName || !trimmedEmail) {
    throw new Error("Name and email are required.");
  }

  const fingerprint = `MOCK-${crypto.randomUUID().slice(0, 8)}-${crypto.randomUUID().slice(0, 8)}`.toUpperCase();
  updateStore((current) => ({
    ...current,
    keys: [
      ...current.keys,
      {
        key_id: fingerprint.slice(-16),
        fingerprint,
        user_ids: [`${trimmedName} <${trimmedEmail}>`],
        has_secret: true,
        algorithm: "RSA",
        bits: 3072,
        created_at: 1712707200,
        expires_at: null,
        trust: "Ultimate",
        capabilities: ["Sign", "Encrypt", "Certify"],
        is_selected_private: false,
        is_selected_recipient: false,
      },
    ],
  }));
}

export async function listKeys(): Promise<KeySummary[]> {
  return getStore().keys;
}

export async function getKeyDetails(fingerprint: string): Promise<KeyDetails> {
  const key = getStore().keys.find((entry) => entry.fingerprint === fingerprint);
  if (!key) {
    throw new Error("Key not found.");
  }
  return {
    summary: key,
    subkeys: [
      {
        fingerprint: `${fingerprint}-SUBKEY`,
        key_id: `${fingerprint}-SUB`.slice(-16),
        algorithm: key.algorithm,
        bits: key.bits,
        created_at: key.created_at,
        expires_at: key.expires_at,
        capabilities: key.capabilities.includes("Encrypt") ? ["Encrypt"] : ["Sign"],
        has_secret: key.has_secret,
      },
    ],
    certifications: [
      {
        signer_key_id: key.key_id,
        signer_fingerprint: key.fingerprint,
        signer_label: key.user_ids[0] ?? "Self",
        subject_user_id: key.user_ids[0] ?? null,
        created_at: key.created_at,
        kind: "Self-signature",
        is_self_signature: true,
      },
    ],
  };
}

export async function getSmartcardStatus(): Promise<SmartcardStatus> {
  return {
    available: true,
    summary: "Hardware token detected on YubiKey mock reader.",
    reader: "YubiKey mock reader",
    serial_number: "00012345",
    application_id: "D2760001240102010000000000010000",
    manufacturer: "Yubico",
    cardholder: "Demo User",
    signature_key: "DEMO-PRIVATE-KEY-001",
    encryption_key: "DEMO-PUBLIC-KEY-002",
    authentication_key: "MOCK-AUTH-KEY-003",
  };
}

export async function listX509Certificates(): Promise<X509CertificateSummary[]> {
  return [
    {
      fingerprint: "X509MOCKFINGERPRINT00112233445566778899AABB",
      key_id: "AABBCCDDEEFF0011",
      subject: "CN=Demo User, O=EncryptKeeper, C=US",
      issuer: "CN=Demo Root CA, O=EncryptKeeper, C=US",
      serial_number: "01A2B3C4",
      validity: "Full",
      algorithm: "RSA",
      bits: 2048,
      created_at: "2025-01-01",
      expires_at: "2027-01-01",
      has_secret: true,
      is_trusted_root: false,
    },
  ];
}

export async function learnX509Card(): Promise<KeyActionResult> {
  return {
    fingerprint: "x509-card",
    summary: "Learned X.509 certificate material from the smartcard.",
  };
}

export async function createX509Certificate(
  commonName: string,
  organization: string,
  email: string,
  expiresAt: string,
  passphrase: string,
): Promise<KeyActionResult> {
  if (!commonName.trim()) {
    throw new Error("Certificate name is required.");
  }
  if (!expiresAt.trim()) {
    throw new Error("Certificate expiry date is required.");
  }
  if (!passphrase) {
    throw new Error("Certificate passphrase is required.");
  }

  const subjectParts = [`CN=${commonName.trim()}`];
  if (organization.trim()) {
    subjectParts.push(`O=${organization.trim()}`);
  }

  return {
    fingerprint: "X509MOCKCREATEDCERT00112233445566778899CCDD",
    summary: `Created X.509 certificate for ${subjectParts.join(",")}.`,
  };
}

export async function importX509Certificate(path: string): Promise<KeyActionResult> {
  if (!path) {
    throw new Error("Choose a certificate file.");
  }
  return {
    fingerprint: "x509",
    summary: `Imported X.509 certificate from ${path}.`,
  };
}

export async function importX509CertificateText(certificateText: string): Promise<KeyActionResult> {
  if (!certificateText.trim()) {
    throw new Error("Paste certificate text first.");
  }
  return {
    fingerprint: "x509",
    summary: "Imported X.509 certificate from pasted text.",
  };
}

export async function exportX509Certificate(
  fingerprint: string,
  outputPath: string,
): Promise<KeyActionResult> {
  if (!fingerprint || !outputPath) {
    throw new Error("Choose a certificate and output file.");
  }
  return {
    fingerprint,
    summary: `Exported X.509 certificate to ${outputPath}.`,
  };
}

export async function exportX509SecretKeyP12(
  fingerprint: string,
  outputPath: string,
): Promise<KeyActionResult> {
  if (!fingerprint || !outputPath) {
    throw new Error("Choose a certificate and output file.");
  }
  return {
    fingerprint,
    summary: `Exported PKCS#12 bundle to ${outputPath}.`,
  };
}

export async function exportX509SecretKeyP8(
  fingerprint: string,
  outputPath: string,
): Promise<KeyActionResult> {
  if (!fingerprint || !outputPath) {
    throw new Error("Choose a certificate and output file.");
  }
  return {
    fingerprint,
    summary: `Exported PKCS#8 key to ${outputPath}.`,
  };
}

export async function changeX509Passphrase(fingerprint: string): Promise<KeyActionResult> {
  if (!fingerprint) {
    throw new Error("Choose a certificate first.");
  }
  return {
    fingerprint,
    summary: `Completed the X.509 passphrase workflow for ${fingerprint}.`,
  };
}

export async function deleteX509Certificate(fingerprint: string): Promise<KeyActionResult> {
  if (!fingerprint) {
    throw new Error("Choose a certificate to remove.");
  }
  return {
    fingerprint,
    summary: `Removed X.509 certificate ${fingerprint}.`,
  };
}

export async function getX509CertificateChain(fingerprint: string): Promise<string> {
  if (!fingerprint) {
    throw new Error("Choose a certificate first.");
  }
  return [
    "Certificate chain",
    `leaf: ${fingerprint}`,
    "issuer: CN=Demo Root CA, O=EncryptKeeper, C=US",
    "status: mock trusted chain",
  ].join("\n");
}

export async function importX509Crl(path: string): Promise<KeyActionResult> {
  if (!path) {
    throw new Error("Choose a CRL file.");
  }
  return {
    fingerprint: "x509-crl",
    summary: `Loaded certificate revocation data from ${path}.`,
  };
}

export async function setX509TrustRoot(
  fingerprint: string,
  trusted: boolean,
): Promise<KeyActionResult> {
  if (!fingerprint) {
    throw new Error("Choose a certificate first.");
  }
  return {
    fingerprint,
    summary: trusted
      ? `Marked ${fingerprint} as a trusted root certificate.`
      : `Removed ${fingerprint} from trusted root certificates.`,
  };
}

export async function exportX509Trustlist(outputPath: string): Promise<KeyActionResult> {
  if (!outputPath) {
    throw new Error("Choose a destination file.");
  }
  return {
    fingerprint: "x509-trustlist",
    summary: `Exported 1 trusted root certificate to ${outputPath}.`,
  };
}

export async function importX509Trustlist(inputPath: string): Promise<KeyActionResult> {
  if (!inputPath) {
    throw new Error("Choose a trust list file.");
  }
  return {
    fingerprint: "x509-trustlist",
    summary: `Imported 1 trusted root certificate from ${inputPath}.`,
  };
}

export async function restartSmartcardService(): Promise<KeyActionResult> {
  return {
    fingerprint: "smartcard",
    summary: "Restarted the smartcard service.",
  };
}

export async function changeSmartcardPin(): Promise<KeyActionResult> {
  return {
    fingerprint: "smartcard",
    summary: "Completed the smartcard PIN workflow.",
  };
}

export async function fetchSmartcardPublicKey(): Promise<KeyActionResult> {
  return {
    fingerprint: "smartcard",
    summary: "Fetched linked public key material from the hardware token.",
  };
}

export async function createSmartcardKeyStubs(): Promise<KeyActionResult> {
  return {
    fingerprint: "smartcard",
    summary: "Created local shadow keys for the hardware token.",
  };
}

export async function generateSmartcardKey(
  slot: string,
  algorithm: string,
  force: boolean,
): Promise<KeyActionResult> {
  if (!slot || !algorithm) {
    throw new Error("Choose a smartcard slot and algorithm.");
  }
  return {
    fingerprint: "smartcard",
    summary: `${force ? "Replaced" : "Generated"} ${algorithm} key material on hardware token slot ${slot}.`,
  };
}

export async function factoryResetSmartcard(): Promise<KeyActionResult> {
  return {
    fingerprint: "smartcard",
    summary: "Factory reset completed for the hardware token.",
  };
}

export async function moveSecretKeyToSmartcard(
  fingerprint: string,
  slot: string,
  force: boolean,
): Promise<KeyActionResult> {
  if (!fingerprint || !slot) {
    throw new Error("Choose a secret key and token slot.");
  }
  return {
    fingerprint,
    summary: `${force ? "Moved" : "Stored"} local secret key ${fingerprint} into hardware token slot ${slot}.`,
  };
}

export async function setKeyExpiry(
  fingerprint: string,
  expire: string,
): Promise<KeyActionResult> {
  const normalized = expire.trim().toLowerCase();
  const expiresAt =
    normalized === "0" || normalized === "never"
      ? null
      : Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60;
  updateStore((current) => ({
    ...current,
    keys: current.keys.map((key) =>
      key.fingerprint === fingerprint ? { ...key, expires_at: expiresAt } : key,
    ),
  }));
  return {
    fingerprint,
    summary:
      expiresAt === null
        ? `Updated expiration for ${fingerprint}.`
        : `Updated expiration for ${fingerprint}.`,
  };
}

export async function setKeyOwnertrust(
  fingerprint: string,
  trust: string,
): Promise<KeyActionResult> {
  const labelByTrust: Record<string, string> = {
    undefined: "Unknown",
    never: "Never",
    marginal: "Marginal",
    full: "Full",
    ultimate: "Ultimate",
  };
  updateStore((current) => ({
    ...current,
    keys: current.keys.map((key) =>
      key.fingerprint === fingerprint
        ? { ...key, trust: labelByTrust[trust] ?? trust }
        : key,
    ),
  }));
  return {
    fingerprint,
    summary: `Updated ownertrust for ${fingerprint} to ${trust}.`,
  };
}

export async function certifyKey(
  fingerprint: string,
  localOnly: boolean,
): Promise<KeyActionResult> {
  const store = getStore();
  if (!store.status.session_unlocked) {
    throw new Error("Unlock the session before certifying keys.");
  }
  if (!store.status.selected_private_key) {
    throw new Error("Select a private key before certifying keys.");
  }
  return {
    fingerprint,
    summary: localOnly
      ? `Added a local certification for ${fingerprint}.`
      : `Certified ${fingerprint}.`,
  };
}

export async function exportRevocationCertificate(
  fingerprint: string,
  passphrase: string,
  _outputPath: string,
): Promise<KeyActionResult> {
  if (!passphrase) {
    throw new Error("Enter the key passphrase.");
  }
  return {
    fingerprint,
    summary: `Exported a revocation certificate for ${fingerprint}.`,
  };
}

export async function getPinnedKeySettings(): Promise<PinnedKeySettings> {
  const raw = window.localStorage.getItem(PINNED_SETTINGS_STORAGE_KEY);
  if (!raw) {
    return {
      private_key_fingerprint: null,
      recipient_fingerprints: [],
    };
  }

  try {
    const parsed = JSON.parse(raw) as PinnedKeySettings;
    return {
      private_key_fingerprint: parsed.private_key_fingerprint ?? null,
      recipient_fingerprints: Array.isArray(parsed.recipient_fingerprints)
        ? parsed.recipient_fingerprints.filter((value): value is string => typeof value === "string")
        : [],
    };
  } catch {
    return {
      private_key_fingerprint: null,
      recipient_fingerprints: [],
    };
  }
}

export async function savePinnedKeySettings(
  privateKeyFingerprint: string | null,
  recipientFingerprints: string[],
): Promise<PinnedKeySettings> {
  const next = {
    private_key_fingerprint: privateKeyFingerprint,
    recipient_fingerprints: recipientFingerprints,
  };
  window.localStorage.setItem(PINNED_SETTINGS_STORAGE_KEY, JSON.stringify(next));
  return next;
}

export async function selectPrivateKey(fingerprint: string): Promise<void> {
  updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      selected_private_key: fingerprint,
    },
  }));
}

export async function exportPublicKey(_fingerprint: string, _outputPath: string): Promise<void> {
  return;
}

export async function exportPrivateKey(
  _fingerprint: string,
  _passphrase: string,
  _outputPath: string,
): Promise<void> {
  return;
}

export async function removeKey(fingerprint: string): Promise<void> {
  updateStore((current) => ({
    ...current,
    keys: current.keys.filter((key) => key.fingerprint !== fingerprint),
    status: {
      ...current.status,
      selected_private_key:
        current.status.selected_private_key === fingerprint
          ? null
          : current.status.selected_private_key,
      selected_recipients: current.status.selected_recipients.filter(
        (value) => value !== fingerprint,
      ),
    },
  }));
}

export async function setRecipients(fingerprints: string[]): Promise<void> {
  updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      selected_recipients: fingerprints,
    },
  }));
}

export async function unlockSession(passphrase: string): Promise<void> {
  const store = getStore();
  if (!store.status.selected_private_key) {
    throw new Error("Select a private key first.");
  }
  if (!passphrase) {
    throw new Error("Enter a passphrase.");
  }
  updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      session_unlocked: true,
      remaining_auto_lock_secs:
        current.status.inactivity_timeout_secs === 0 ? null : current.status.inactivity_timeout_secs,
    },
  }));
}

export async function lockSession(): Promise<void> {
  updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      session_unlocked: false,
      remaining_auto_lock_secs: null,
    },
  }));
}

export async function updatePreferences(
  recursiveScan: boolean,
  inactivityTimeoutSecs: number,
  autoSave: boolean,
): Promise<SessionStatus> {
  const store = updateStore((current) => ({
    ...current,
    status: {
      ...current.status,
      recursive_scan: recursiveScan,
      inactivity_timeout_secs: inactivityTimeoutSecs,
      remaining_auto_lock_secs:
        current.status.session_unlocked && inactivityTimeoutSecs > 0 ? inactivityTimeoutSecs : null,
      auto_save: autoSave,
    },
  }));
  return store.status;
}

export function isMockBackend() {
  return true;
}

export async function resetMockData(): Promise<void> {
  window.localStorage.removeItem(STORAGE_KEY);
  getStore();
}
