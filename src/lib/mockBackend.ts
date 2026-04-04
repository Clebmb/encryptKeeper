import type { KeySummary, NoteSummary, OpenNoteResult, SessionStatus } from "../types";
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

const defaultStatus: SessionStatus = {
  vault_kind: "none",
  vault_path: null,
  archive_unlocked: false,
  session_unlocked: false,
  selected_private_key: null,
  selected_recipients: [],
  inactivity_timeout_secs: 900,
  remaining_auto_lock_secs: null,
  recursive_scan: true,
  auto_save: false,
};

const demoKeys: KeySummary[] = [
  {
    fingerprint: "DEMO-PRIVATE-KEY-001",
    user_ids: ["Demo User <demo@encryptkeeper.local>"],
    has_secret: true,
    is_selected_private: false,
    is_selected_recipient: false,
  },
  {
    fingerprint: "DEMO-PUBLIC-KEY-002",
    user_ids: ["Team Recipient <team@encryptkeeper.local>"],
    has_secret: false,
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
      recursive_scan: recursive,
    },
  }));
  return store.notes;
}

export async function listNotes(): Promise<NoteSummary[]> {
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

export async function saveNote(noteId: string, content: string): Promise<void> {
  updateStore((current) => ({
    ...current,
    notes: current.notes.map((note) => (note.id === noteId ? { ...note, content } : note)),
  }));
}

export async function createNote(name: string, content: string): Promise<NoteSummary> {
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

export async function importKey(path: string): Promise<void> {
  const pathSegments = path.split(/[/\\]/);
  const name = pathSegments[pathSegments.length - 1] ?? "Imported Key";
  const fingerprint = `IMPORTED-${name}-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();
  updateStore((current) => ({
    ...current,
    keys: [
      ...current.keys,
      {
        fingerprint,
        user_ids: [`${name} <imported@encryptkeeper.local>`],
        has_secret: true,
        is_selected_private: false,
        is_selected_recipient: false,
      },
    ],
  }));
}

export async function listKeys(): Promise<KeySummary[]> {
  return getStore().keys;
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
