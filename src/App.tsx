import { useEffect, useMemo, useRef, useState } from "react";
import {
  closestCenter,
  DndContext,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from "@dnd-kit/core";
import {
  arrayMove,
  SortableContext,
  useSortable,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import {
  Settings,
  ArrowDownUp,
  FileKey,
  FolderOpen,
  GripVertical,
  Lock,
  NotebookPen,
  Plus,
  RefreshCcw,
  Save,
  Search,
  Shield,
  Trash2,
  Unlock,
} from "lucide-react";
import { confirm, open, save as saveDialog } from "@tauri-apps/plugin-dialog";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  createNote,
  createKey,
  deleteNote,
  exportPrivateKey,
  exportPublicKey,
  getBackendMode,
  getStatus,
  importKey,
  listKeys,
  listNotes,
  lockSession,
  openFolderVault,
  openNote,
  previewPgpBlock,
  removeKey,
  renameNote,
  saveNote,
  selectPrivateKey,
  setRecipients,
  unlockSession,
  updatePreferences,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { normalizeNoteName } from "@/lib/noteName";
import type { KeySummary, NoteSummary, SessionStatus } from "@/types";

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

const KEY_ORDER_STORAGE_KEY = "encryptkeeper.key-order";

function formatFingerprint(fingerprint: string) {
  if (fingerprint.length <= 18) {
    return fingerprint;
  }
  return `${fingerprint.slice(0, 10)}...${fingerprint.slice(-8)}`;
}

function formatTimeout(seconds: number) {
  if (seconds === 0) {
    return "Auto-lock off";
  }
  const minutes = Math.max(1, Math.round(seconds / 60));
  return `${minutes} min auto-lock`;
}

function formatCountdown(seconds: number | null, unlocked: boolean, timeoutSecs: number) {
  if (timeoutSecs === 0) {
    return "Auto-lock disabled";
  }
  if (!unlocked) {
    return "Starts after unlock";
  }
  if (seconds === null) {
    return "Tracking inactivity";
  }
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `Locks in ${mins}:${secs.toString().padStart(2, "0")}`;
}

function activeVaultLabel(vaultKind: SessionStatus["vault_kind"]) {
  return vaultKind === "none" ? "No vault" : `${vaultKind} vault`;
}

function joinPath(base: string, fileName: string) {
  if (base.endsWith("\\") || base.endsWith("/")) {
    return `${base}${fileName}`;
  }
  return `${base}\\${fileName}`;
}

function loadStoredKeyOrder() {
  if (typeof window === "undefined") {
    return [] as string[];
  }

  try {
    const raw = window.localStorage.getItem(KEY_ORDER_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : [];
  } catch {
    return [] as string[];
  }
}

function keyDisplayName(key: KeySummary) {
  return key.user_ids[0]?.split("<")[0]?.trim() || "Key";
}

function keyFileStem(key: KeySummary) {
  const baseName = keyDisplayName(key)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24);
  const fingerprintTail = key.fingerprint.slice(-6).toLowerCase();
  return `${baseName || "key"}-${fingerprintTail}`;
}

interface SortableKeyCardProps {
  keyItem: KeySummary;
  onPrivateKeySelection: (fingerprint: string) => void;
  onRecipientSelection: (fingerprint: string, checked: boolean) => void;
  onExportPublic: (key: KeySummary) => void;
  onOpenExportDialog: (key: KeySummary, mode: "private" | "both") => void;
  onRemoveKey: (key: KeySummary) => void;
}

function SortableKeyCard({
  keyItem,
  onPrivateKeySelection,
  onRecipientSelection,
  onExportPublic,
  onOpenExportDialog,
  onRemoveKey,
}: SortableKeyCardProps) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: keyItem.fingerprint,
  });

  return (
    <div
      ref={setNodeRef}
      style={{
        transform: CSS.Transform.toString(transform),
        transition,
      }}
      className={cn(
        "rounded-lg border border-border/70 bg-background/40 p-3",
        isDragging && "opacity-70 shadow-lg",
      )}
    >
      <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3">
        <button
          className="mt-0.5 shrink-0 cursor-grab rounded-md border border-border/70 bg-background/60 p-1 text-muted-foreground hover:bg-accent active:cursor-grabbing"
          aria-label={`Reorder ${keyDisplayName(keyItem)}`}
          title="Drag to reorder"
          {...attributes}
          {...listeners}
        >
          <GripVertical className="h-4 w-4" />
        </button>
        <div className="min-w-0">
          <div className="flex flex-col gap-2">
            <div className="truncate text-sm font-medium">{keyItem.user_ids[0] ?? "Unnamed key"}</div>
            <code className="truncate text-xs text-muted-foreground">
              {formatFingerprint(keyItem.fingerprint)}
            </code>
            <div>
              <Badge variant={keyItem.has_secret ? "default" : "secondary"} className="shrink-0">
                {keyItem.has_secret ? "Private" : "Public"}
              </Badge>
            </div>
          </div>
        </div>
        <Button
          size="icon"
          variant="ghost"
          className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
          onClick={() => void onRemoveKey(keyItem)}
          aria-label={`Remove ${keyDisplayName(keyItem)}`}
          title="Remove key"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>
      <div className="mt-2 grid gap-2">
        <div className="grid gap-2 text-xs text-muted-foreground">
          <label className="flex items-center gap-2">
            <input
              type="radio"
              name="private-key"
              checked={keyItem.is_selected_private}
              disabled={!keyItem.has_secret}
              onChange={() => void onPrivateKeySelection(keyItem.fingerprint)}
            />
            Use to decrypt
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={keyItem.is_selected_recipient}
              onChange={(event) => void onRecipientSelection(keyItem.fingerprint, event.target.checked)}
            />
            Encrypt to this key
          </label>
        </div>
        <div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline" className="w-full px-2">
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" side="right" className="w-40">
              <DropdownMenuItem onClick={() => void onExportPublic(keyItem)}>Public</DropdownMenuItem>
              <DropdownMenuItem
                disabled={!keyItem.has_secret}
                onClick={() => void onOpenExportDialog(keyItem, "private")}
              >
                Private
              </DropdownMenuItem>
              <DropdownMenuItem
                disabled={!keyItem.has_secret}
                onClick={() => void onOpenExportDialog(keyItem, "both")}
              >
                Both
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </div>
  );
}

export function App() {
  const backendMode = getBackendMode();
  const [status, setStatus] = useState<SessionStatus>(defaultStatus);
  const [keys, setKeys] = useState<KeySummary[]>([]);
  const [notes, setNotes] = useState<NoteSummary[]>([]);
  const [selectedNote, setSelectedNote] = useState<NoteSummary | null>(null);
  const [editorValue, setEditorValue] = useState("");
  const [search, setSearch] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [timeoutMinutesInput, setTimeoutMinutesInput] = useState("15");
  const [countdownSecs, setCountdownSecs] = useState<number | null>(null);
  const [isPgpPreviewOpen, setIsPgpPreviewOpen] = useState(false);
  const [pgpPreview, setPgpPreview] = useState("");
  const [pgpPreviewError, setPgpPreviewError] = useState<string | null>(null);
  const [pgpPreviewBusy, setPgpPreviewBusy] = useState(false);
  const [isCreateKeyOpen, setIsCreateKeyOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyEmail, setNewKeyEmail] = useState("");
  const [newKeyPassphrase, setNewKeyPassphrase] = useState("");
  const [isExportDialogOpen, setIsExportDialogOpen] = useState(false);
  const [exportMode, setExportMode] = useState<"private" | "both">("private");
  const [exportTargetKey, setExportTargetKey] = useState<KeySummary | null>(null);
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [keyOrder, setKeyOrder] = useState<string[]>(() => loadStoredKeyOrder());
  const wasUnlockedRef = useRef(status.session_unlocked);
  const previewRequestRef = useRef(0);
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 6 } }));

  async function refreshStatus() {
    const nextStatus = await getStatus();
    setStatus(nextStatus);
    setCountdownSecs(nextStatus.remaining_auto_lock_secs);
    setTimeoutMinutesInput(
      nextStatus.inactivity_timeout_secs === 0
        ? ""
        : String(Math.max(1, Math.round(nextStatus.inactivity_timeout_secs / 60))),
    );
  }

  async function refreshKeys() {
    setKeys(await listKeys());
  }

  async function refreshNotes() {
    setNotes(await listNotes());
  }

  useEffect(() => {
    void (async () => {
      setBusy("Loading workspace...");
      try {
        await Promise.all([refreshStatus(), refreshKeys(), refreshNotes()]);
      } catch (cause) {
        setError(String(cause));
      } finally {
        setBusy(null);
      }
    })();

    const timer = window.setInterval(() => {
      void refreshStatus().catch(() => undefined);
    }, 10_000);

    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    setKeyOrder((current) => {
      const nextFingerprints = keys.map((key) => key.fingerprint);
      const kept = current.filter((fingerprint) => nextFingerprints.includes(fingerprint));
      const added = [...nextFingerprints]
        .filter((fingerprint) => !kept.includes(fingerprint))
        .sort((left, right) => left.localeCompare(right));
      return [...kept, ...added];
    });
  }, [keys]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(KEY_ORDER_STORAGE_KEY, JSON.stringify(keyOrder));
  }, [keyOrder]);

  useEffect(() => {
    if (!status.auto_save || !dirty || !selectedNote || !status.session_unlocked) {
      return;
    }
    const timer = window.setTimeout(() => {
      void handleSave();
    }, 2_000);
    return () => window.clearTimeout(timer);
  }, [dirty, editorValue, selectedNote, status.auto_save, status.session_unlocked]);

  useEffect(() => {
    setCountdownSecs(status.remaining_auto_lock_secs);
  }, [status.remaining_auto_lock_secs]);

  useEffect(() => {
    if (wasUnlockedRef.current && !status.session_unlocked) {
      setEditorValue("");
      setDirty(false);
      setIsPgpPreviewOpen(false);
      setPgpPreview("");
      setPgpPreviewError(null);
    }
    wasUnlockedRef.current = status.session_unlocked;
  }, [status.session_unlocked]);

  useEffect(() => {
    if (!status.session_unlocked || status.inactivity_timeout_secs === 0 || countdownSecs === null) {
      return;
    }

    const timer = window.setInterval(() => {
      setCountdownSecs((current) => {
        if (current === null) {
          return null;
        }
        return current > 0 ? current - 1 : 0;
      });
    }, 1_000);

    return () => window.clearInterval(timer);
  }, [status.session_unlocked, status.inactivity_timeout_secs, countdownSecs]);

  useEffect(() => {
    if (!isPgpPreviewOpen) {
      return;
    }

    if (!selectedNote || !status.session_unlocked) {
      setPgpPreview("");
      setPgpPreviewError(null);
      setPgpPreviewBusy(false);
      return;
    }

    const requestId = previewRequestRef.current + 1;
    previewRequestRef.current = requestId;
    setPgpPreviewBusy(true);

    const timer = window.setTimeout(() => {
      void previewPgpBlock(editorValue)
        .then((block) => {
          if (previewRequestRef.current !== requestId) {
            return;
          }
          setPgpPreview(block);
          setPgpPreviewError(null);
        })
        .catch((cause) => {
          if (previewRequestRef.current !== requestId) {
            return;
          }
          setPgpPreview("");
          setPgpPreviewError(cause instanceof Error ? cause.message : String(cause));
        })
        .finally(() => {
          if (previewRequestRef.current === requestId) {
            setPgpPreviewBusy(false);
          }
        });
    }, 250);

    return () => window.clearTimeout(timer);
  }, [editorValue, isPgpPreviewOpen, selectedNote, status.session_unlocked, status.selected_recipients]);

  const filteredNotes = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) {
      return notes;
    }
    return notes.filter((note) => note.relative_path.toLowerCase().includes(needle));
  }, [notes, search]);

  const recipientsLabel =
    status.selected_recipients.length === 0
      ? "No recipients"
      : `${status.selected_recipients.length} recipient${status.selected_recipients.length === 1 ? "" : "s"}`;

  const orderedKeys = useMemo(() => {
    const rank = new Map(keyOrder.map((fingerprint, index) => [fingerprint, index]));
    return [...keys].sort((left, right) => {
      const leftRank = rank.get(left.fingerprint) ?? Number.MAX_SAFE_INTEGER;
      const rightRank = rank.get(right.fingerprint) ?? Number.MAX_SAFE_INTEGER;
      return leftRank - rightRank;
    });
  }, [keyOrder, keys]);

  async function withBusy<T>(label: string, work: () => Promise<T>) {
    setBusy(label);
    setError(null);
    try {
      return await work();
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      setError(message);
      throw cause;
    } finally {
      setBusy(null);
    }
  }

  async function handleOpenFolder() {
    try {
      setError(null);
      const selected =
        backendMode === "tauri"
          ? await open({ directory: true, multiple: false, title: "Open Folder Vault" })
          : window.prompt("Mock mode folder label", "Demo Vault");
      if (!selected || Array.isArray(selected)) {
        return;
      }
      await withBusy("Opening vault...", async () => {
        const nextNotes = await openFolderVault(selected, status.recursive_scan);
        setNotes(nextNotes);
        setSelectedNote(null);
        setEditorValue("");
        setDirty(false);
        await refreshStatus();
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleImportKey() {
    try {
      setError(null);
      const selected =
        backendMode === "tauri"
          ? await open({
              directory: false,
              multiple: true,
              title: "Import OpenPGP Key",
              filters: [{ name: "Key Files", extensions: ["asc", "txt", "gpg", "pgp", "key"] }],
            })
          : window.prompt("Mock mode imported key label", "mock-private-key.asc");
      if (!selected) {
        return;
      }
      await withBusy("Importing key...", async () => {
        const paths = Array.isArray(selected) ? selected : [selected];
        for (const path of paths) {
          await importKey(path);
        }
        await refreshKeys();
        await refreshStatus();
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleUnlock() {
    await withBusy("Unlocking session...", async () => {
      await unlockSession(passphrase);
      setPassphrase("");
      await refreshStatus();
    });
  }

  async function handleSelectNote(note: NoteSummary) {
    await withBusy(`Opening ${note.name}...`, async () => {
      const opened = await openNote(note.id);
      setSelectedNote(opened.note);
      setEditorValue(opened.content);
      setDirty(false);
      await refreshStatus();
    });
  }

  async function handleSave() {
    if (!selectedNote) {
      return;
    }
    await withBusy(`Saving ${selectedNote.name}...`, async () => {
      await saveNote(selectedNote.id, editorValue);
      setDirty(false);
      await refreshNotes();
    });
  }

  async function handleTogglePgpPreview() {
    if (isPgpPreviewOpen) {
      setIsPgpPreviewOpen(false);
      setPgpPreview("");
      setPgpPreviewError(null);
      setPgpPreviewBusy(false);
      return;
    }

    setIsPgpPreviewOpen(true);
    setPgpPreview("");
    setPgpPreviewError(null);
  }

  async function handleCreateKey() {
    await withBusy("Creating key...", async () => {
      await createKey(newKeyName, newKeyEmail, newKeyPassphrase);
      setIsCreateKeyOpen(false);
      setNewKeyName("");
      setNewKeyEmail("");
      setNewKeyPassphrase("");
      await refreshKeys();
      await refreshStatus();
    });
  }

  async function handleExportPublic(key: KeySummary) {
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export Public Key",
            defaultPath: `${keyFileStem(key)}-public.asc`,
            filters: [{ name: "ASCII-armored keys", extensions: ["asc"] }],
          })
        : `${key.fingerprint}-public.asc`;
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting public key...", async () => {
      await exportPublicKey(key.fingerprint, outputPath);
    });
  }

  function openExportDialog(key: KeySummary, mode: "private" | "both") {
    setExportTargetKey(key);
    setExportMode(mode);
    setExportPassphrase("");
    setIsExportDialogOpen(true);
  }

  async function handleConfirmExport() {
    if (!exportTargetKey || !exportPassphrase) {
      return;
    }

    if (exportMode === "private") {
      const outputPath =
        backendMode === "tauri"
          ? await saveDialog({
              title: "Export Private Key",
              defaultPath: `${keyFileStem(exportTargetKey)}-private.asc`,
              filters: [{ name: "ASCII-armored keys", extensions: ["asc"] }],
            })
          : `${keyFileStem(exportTargetKey)}-private.asc`;
      if (!outputPath || Array.isArray(outputPath)) {
        return;
      }

      await withBusy("Exporting private key...", async () => {
        await exportPrivateKey(exportTargetKey.fingerprint, exportPassphrase, outputPath);
      });
    } else {
      const destination =
        backendMode === "tauri"
          ? await open({ directory: true, multiple: false, title: "Export Public and Private Keys" })
          : ".";
      if (!destination || Array.isArray(destination)) {
        return;
      }

      const publicPath = joinPath(destination, `${keyFileStem(exportTargetKey)}-public.asc`);
      const privatePath = joinPath(destination, `${keyFileStem(exportTargetKey)}-private.asc`);

      await withBusy("Exporting public and private keys...", async () => {
        await exportPublicKey(exportTargetKey.fingerprint, publicPath);
        await exportPrivateKey(exportTargetKey.fingerprint, exportPassphrase, privatePath);
      });
    }

    setIsExportDialogOpen(false);
    setExportTargetKey(null);
    setExportPassphrase("");
  }

  async function handleCreate() {
    const name = window.prompt("New note name");
    if (!name) {
      return;
    }
    const normalized = normalizeNoteName(name);
    await withBusy(`Creating ${normalized}...`, async () => {
      const created = await createNote(normalized, "");
      await refreshNotes();
      await handleSelectNote(created);
    });
  }

  async function handleRename() {
    if (!selectedNote) {
      return;
    }
    const newName = window.prompt("Rename note", selectedNote.relative_path);
    if (!newName) {
      return;
    }
    const normalized = normalizeNoteName(newName);
    await withBusy(`Renaming ${selectedNote.name}...`, async () => {
      const renamed = await renameNote(selectedNote.id, normalized);
      await refreshNotes();
      setSelectedNote(renamed);
    });
  }

  async function handleDelete() {
    if (!selectedNote) {
      return;
    }
    const approved =
      backendMode === "tauri"
        ? await confirm(`Delete ${selectedNote.relative_path}?`, {
            title: "Delete note",
            kind: "warning",
            okLabel: "Delete",
            cancelLabel: "Cancel",
          })
        : window.confirm(`Delete ${selectedNote.relative_path}?`);
    if (!approved) {
      return;
    }
    await withBusy(`Deleting ${selectedNote.name}...`, async () => {
      await deleteNote(selectedNote.id);
      await refreshNotes();
      setSelectedNote(null);
      setEditorValue("");
      setDirty(false);
    });
  }

  async function handlePrivateKeySelection(fingerprint: string) {
    await withBusy("Selecting private key...", async () => {
      await selectPrivateKey(fingerprint);
      await refreshKeys();
      await refreshStatus();
    });
  }

  async function handleRecipientSelection(fingerprint: string, checked: boolean) {
    const next = checked
      ? [...status.selected_recipients, fingerprint]
      : status.selected_recipients.filter((value) => value !== fingerprint);
    await withBusy("Updating recipients...", async () => {
      await setRecipients(next);
      await refreshKeys();
      await refreshStatus();
    });
  }

  async function handleRemoveKey(key: KeySummary) {
    const approved =
      backendMode === "tauri"
        ? await confirm(`Remove ${keyDisplayName(key)} from the keyring?`, {
            title: "Remove key",
            kind: "warning",
            okLabel: "Remove",
            cancelLabel: "Cancel",
          })
        : window.confirm(`Remove ${keyDisplayName(key)} from the keyring?`);
    if (!approved) {
      return;
    }

    await withBusy("Removing key...", async () => {
      await removeKey(key.fingerprint, key.has_secret);
      setKeyOrder((current) => current.filter((fingerprint) => fingerprint !== key.fingerprint));
      await refreshKeys();
      await refreshStatus();
    });
  }

  function moveKey(draggedFingerprint: string, targetFingerprint: string) {
    if (draggedFingerprint === targetFingerprint) {
      return;
    }

    setKeyOrder((current) => {
      const next = current.filter((fingerprint) => fingerprint !== draggedFingerprint);
      const targetIndex = next.indexOf(targetFingerprint);
      if (targetIndex === -1) {
        return [...next, draggedFingerprint];
      }
      next.splice(targetIndex, 0, draggedFingerprint);
      return next;
    });
  }

  function handleKeyDragEnd(event: DragEndEvent) {
    const { active, over } = event;
    if (!over || active.id === over.id) {
      return;
    }

    setKeyOrder((current) => {
      const oldIndex = current.indexOf(String(active.id));
      const newIndex = current.indexOf(String(over.id));
      if (oldIndex === -1 || newIndex === -1) {
        return current;
      }
      return arrayMove(current, oldIndex, newIndex);
    });
  }

  async function handlePreferenceChange(
    next: Partial<Pick<SessionStatus, "recursive_scan" | "inactivity_timeout_secs" | "auto_save">>,
  ) {
    const updated = await withBusy("Updating preferences...", async () =>
      updatePreferences(
        next.recursive_scan ?? status.recursive_scan,
        next.inactivity_timeout_secs ?? status.inactivity_timeout_secs,
        next.auto_save ?? status.auto_save,
      ),
    );
    setStatus(updated);
    if (status.vault_kind !== "none") {
      await refreshNotes();
    }
  }

  async function handleTimeoutInputCommit() {
    const trimmed = timeoutMinutesInput.trim();
    const minutes = Number(trimmed);
    if (!trimmed || Number.isNaN(minutes) || minutes < 1) {
      setTimeoutMinutesInput(
        status.inactivity_timeout_secs === 0
          ? ""
          : String(Math.max(1, Math.round(status.inactivity_timeout_secs / 60))),
      );
      return;
    }

    await handlePreferenceChange({ inactivity_timeout_secs: minutes * 60 });
  }

  async function handleAutoLockToggle(enabled: boolean) {
    if (!enabled) {
      setTimeoutMinutesInput("");
      await handlePreferenceChange({ inactivity_timeout_secs: 0 });
      return;
    }

    const nextMinutes = Number(timeoutMinutesInput.trim());
    const safeMinutes = Number.isNaN(nextMinutes) || nextMinutes < 1 ? 15 : nextMinutes;
    setTimeoutMinutesInput(String(safeMinutes));
    await handlePreferenceChange({ inactivity_timeout_secs: safeMinutes * 60 });
  }

  return (
    <div className="min-h-screen surface-grid">
      <div className="container max-w-6xl py-4">
        <div className="space-y-4">
          <Dialog open={isCreateKeyOpen} onOpenChange={setIsCreateKeyOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create OpenPGP Key</DialogTitle>
                <DialogDescription>
                  Create a new keypair in your local GnuPG keyring.
                </DialogDescription>
              </DialogHeader>
              <div className="flex flex-col gap-3">
                <Input
                  value={newKeyName}
                  onChange={(event) => setNewKeyName(event.target.value)}
                  placeholder="Name"
                />
                <Input
                  value={newKeyEmail}
                  onChange={(event) => setNewKeyEmail(event.target.value)}
                  placeholder="Email"
                  type="email"
                />
                <Input
                  value={newKeyPassphrase}
                  onChange={(event) => setNewKeyPassphrase(event.target.value)}
                  placeholder="Key passphrase"
                  type="password"
                />
              </div>
              <DialogFooter className="gap-2">
                <Button variant="ghost" onClick={() => setIsCreateKeyOpen(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => void handleCreateKey()}
                  disabled={!newKeyName.trim() || !newKeyEmail.trim() || !newKeyPassphrase}
                >
                  Create Key
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isExportDialogOpen} onOpenChange={setIsExportDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>
                  {exportMode === "both" ? "Export Public and Private Keys" : "Export Private Key"}
                </DialogTitle>
                <DialogDescription>
                  {exportTargetKey
                    ? `Enter the passphrase for ${keyDisplayName(exportTargetKey)}.`
                    : "Enter the key passphrase to continue."}
                </DialogDescription>
              </DialogHeader>
              <div className="flex flex-col gap-3">
                <Input
                  value={exportPassphrase}
                  onChange={(event) => setExportPassphrase(event.target.value)}
                  placeholder="Key passphrase"
                  type="password"
                />
                {exportTargetKey ? (
                  <div className="rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-xs text-muted-foreground">
                    {exportMode === "both"
                      ? `Files: ${keyFileStem(exportTargetKey)}-public.asc and ${keyFileStem(exportTargetKey)}-private.asc`
                      : `File: ${keyFileStem(exportTargetKey)}-private.asc`}
                  </div>
                ) : null}
              </div>
              <DialogFooter className="gap-2">
                <Button
                  variant="ghost"
                  onClick={() => {
                    setIsExportDialogOpen(false);
                    setExportTargetKey(null);
                    setExportPassphrase("");
                  }}
                >
                  Cancel
                </Button>
                <Button onClick={() => void handleConfirmExport()} disabled={!exportPassphrase}>
                  Continue
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Card className="border-white/10 bg-card/75">
            <CardContent className="flex flex-col gap-4 p-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <h1 className="text-2xl font-semibold tracking-tight">encryptKeeper</h1>
                </div>
                <div className="flex flex-wrap gap-2">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button size="icon" variant="ghost" aria-label="Preferences" title="Preferences">
                        <Settings className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" side="bottom" className="w-56">
                      <div className="flex items-center justify-between gap-3 px-2 py-2">
                        <div>
                          <div className="text-sm font-medium">Recursive scan</div>
                          <div className="text-xs text-muted-foreground">Scan nested folders</div>
                        </div>
                        <Switch
                          checked={status.recursive_scan}
                          onCheckedChange={(checked) =>
                            void handlePreferenceChange({ recursive_scan: checked })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between gap-3 px-2 py-2">
                        <div>
                          <div className="text-sm font-medium">Auto-save</div>
                          <div className="text-xs text-muted-foreground">Save after idle</div>
                        </div>
                        <Switch
                          checked={status.auto_save}
                          onCheckedChange={(checked) =>
                            void handlePreferenceChange({ auto_save: checked })
                          }
                        />
                      </div>
                    </DropdownMenuContent>
                  </DropdownMenu>
                  <Button size="sm" onClick={() => void handleOpenFolder()}>
                    <FolderOpen className="h-4 w-4" />
                    Open Vault
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => void handleUnlock()}
                    disabled={!status.selected_private_key || !passphrase}
                  >
                    <Unlock className="h-4 w-4" />
                    Unlock
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => void lockSession().then(refreshStatus)}>
                    <Lock className="h-4 w-4" />
                    Lock
                  </Button>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <Badge variant={status.session_unlocked ? "default" : "secondary"}>
                  {status.session_unlocked ? "Unlocked" : "Locked"}
                </Badge>
                <Badge variant="outline">
                  {status.vault_path ? activeVaultLabel(status.vault_kind) : "No vault"}
                </Badge>
                <Badge variant="outline">{notes.length} notes</Badge>
                <Badge variant="outline">{recipientsLabel}</Badge>
              </div>

              <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_220px]">
                <div className="space-y-3">
                  <Input
                    type="password"
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                    placeholder="Private key passphrase"
                  />
                  <div className="flex items-center gap-3 rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-xs text-muted-foreground">
                    <span className="truncate">
                      {status.selected_private_key
                        ? `Active key ${formatFingerprint(status.selected_private_key)}`
                        : "No private key selected"}
                    </span>
                  </div>
                </div>
                <div className="rounded-lg border border-border/70 bg-background/40 px-3 py-2">
                  <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">
                    Auto-Lock Timer
                  </div>
                  <div className="flex items-center gap-2">
                    <Input
                      className="h-8"
                      type="number"
                      min={1}
                      step={1}
                      disabled={status.inactivity_timeout_secs === 0}
                      value={timeoutMinutesInput}
                      placeholder="Minutes"
                      onChange={(event) => setTimeoutMinutesInput(event.target.value)}
                      onBlur={() => void handleTimeoutInputCommit()}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") {
                          void handleTimeoutInputCommit();
                        }
                      }}
                    />
                    <span className="text-xs text-muted-foreground">min</span>
                    <label className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Switch
                        checked={status.inactivity_timeout_secs !== 0}
                        onCheckedChange={(checked) => void handleAutoLockToggle(checked)}
                      />
                      On
                    </label>
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    {formatCountdown(
                      countdownSecs,
                      status.session_unlocked,
                      status.inactivity_timeout_secs,
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="space-y-2">
            {status.session_unlocked ? (
              <Card className="border-amber-500/20 bg-amber-500/8">
                <CardContent className="flex items-center gap-2 p-3 text-sm text-amber-100">
                  <Shield className="h-4 w-4" />
                  Vault is unlocked for this session.
                </CardContent>
              </Card>
            ) : null}
            {backendMode === "mock" ? (
              <Card className="border-white/10 bg-muted/30">
                <CardContent className="p-3 text-sm text-muted-foreground">
                  Mock mode is active. No real encryption or file access is happening.
                </CardContent>
              </Card>
            ) : null}
            {error ? (
              <Card className="border-red-500/20 bg-red-500/10">
                <CardContent className="p-3 text-sm text-red-100">{error}</CardContent>
              </Card>
            ) : null}
          </div>

          <div className="grid gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
            <aside className="space-y-4">
              <Card className="border-white/10 bg-card/75">
                <CardHeader className="space-y-3 pb-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <CardTitle className="text-base">Notes</CardTitle>
                    </div>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="icon" onClick={() => void refreshNotes()}>
                        <RefreshCcw className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => void handleCreate()}
                        disabled={status.vault_kind === "none"}
                      >
                        <NotebookPen className="h-4 w-4" />
                        New
                      </Button>
                    </div>
                  </div>
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      className="h-9 pl-9"
                      type="search"
                      value={search}
                      placeholder="Search notes"
                      onChange={(event) => setSearch(event.target.value)}
                    />
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <ScrollArea className="h-[280px] pr-3">
                    <div className="space-y-2">
                      {filteredNotes.length === 0 ? (
                        <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                          No notes found.
                        </div>
                      ) : (
                        filteredNotes.map((note) => (
                          <button
                            key={note.id}
                            className={cn(
                              "w-full rounded-lg border px-3 py-3 text-left transition-colors",
                              selectedNote?.id === note.id
                                ? "border-primary/40 bg-primary/10"
                                : "border-border/70 bg-background/40 hover:bg-accent",
                            )}
                            onClick={() => void handleSelectNote(note)}
                          >
                            <div className="truncate text-sm font-medium">{note.name}</div>
                            <div className="mt-1 truncate text-xs text-muted-foreground">
                              {note.relative_path}
                            </div>
                          </button>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card className="border-white/10 bg-card/75">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
                  <div>
                    <CardTitle className="text-base">Keys</CardTitle>
                  </div>
                  <div className="grid grid-cols-[auto_auto] items-center gap-x-2 gap-y-2">
                    <div className="row-span-2 flex items-center">
                      <Button variant="ghost" size="icon" onClick={() => void refreshKeys()}>
                        <RefreshCcw className="h-4 w-4" />
                      </Button>
                    </div>
                    <Button size="sm" variant="secondary" onClick={() => setIsCreateKeyOpen(true)}>
                      <Plus className="h-4 w-4" />
                      Create
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => void handleImportKey()}>
                      <FileKey className="h-4 w-4" />
                      Import
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 pt-0">
                  <ScrollArea className="h-[340px] pr-3">
                    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleKeyDragEnd}>
                    <SortableContext
                      items={orderedKeys.map((key) => key.fingerprint)}
                      strategy={verticalListSortingStrategy}
                    >
                    <div className="space-y-2">
                      {orderedKeys.length === 0 ? (
                        <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                          No keys imported yet.
                        </div>
                      ) : (
                        orderedKeys.map((key) => (
                          <SortableKeyCard
                            key={key.fingerprint}
                            keyItem={key}
                            onPrivateKeySelection={(fingerprint) => void handlePrivateKeySelection(fingerprint)}
                            onRecipientSelection={(fingerprint, checked) =>
                              void handleRecipientSelection(fingerprint, checked)
                            }
                            onExportPublic={(currentKey) => void handleExportPublic(currentKey)}
                            onOpenExportDialog={(currentKey, mode) => openExportDialog(currentKey, mode)}
                            onRemoveKey={(currentKey) => void handleRemoveKey(currentKey)}
                          />
                        ))
                      )}
                    </div>
                    </SortableContext>
                    </DndContext>
                  </ScrollArea>
                </CardContent>
              </Card>
            </aside>

            <Card className="border-white/10 bg-card/75 lg:flex lg:min-h-[calc(100vh-12rem)] lg:flex-col">
              <CardHeader className="space-y-3 pb-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <CardTitle className="truncate text-base">
                      {selectedNote?.relative_path ?? "Editor"}
                    </CardTitle>
                    {dirty ? <CardDescription>Unsaved changes</CardDescription> : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" onClick={() => void handleSave()} disabled={!dirty || !selectedNote}>
                      <Save className="h-4 w-4" />
                      Save
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => void handleTogglePgpPreview()}
                      disabled={!selectedNote || !status.session_unlocked}
                    >
                      {isPgpPreviewOpen ? "Hide PGP Block" : "View PGP Block"}
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => void handleRename()}
                      disabled={!selectedNote}
                    >
                      Rename
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => void handleDelete()}
                      disabled={!selectedNote}
                    >
                      <Trash2 className="h-4 w-4" />
                      Delete
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="pt-0 lg:flex lg:flex-1 lg:flex-col">
                {isPgpPreviewOpen ? (
                  <div className="mb-3 rounded-xl border border-border/70 bg-background/50 p-3">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="text-sm font-medium">PGP Block Preview</div>
                      <div className="text-xs text-muted-foreground">
                        {pgpPreviewBusy ? "Updating..." : "Live preview"}
                      </div>
                    </div>
                    {pgpPreviewError ? (
                      <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-xs text-red-100">
                        {pgpPreviewError}
                      </div>
                    ) : (
                      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border/70 bg-background/70 p-3 font-mono text-xs leading-5 text-muted-foreground">
                        {pgpPreview || "Generating armored message..."}
                      </pre>
                    )}
                  </div>
                ) : null}
                <Textarea
                  className="min-h-[680px] rounded-xl bg-background/70 font-mono text-sm leading-6 lg:min-h-0 lg:flex-1"
                  value={editorValue}
                  placeholder="Open or create a note to edit plaintext content here."
                  onChange={(event) => {
                    setEditorValue(event.target.value);
                    setDirty(true);
                  }}
                  spellCheck={false}
                />
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
