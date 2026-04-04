import { useEffect, useMemo, useState } from "react";
import {
  FileKey,
  FolderOpen,
  KeyRound,
  Lock,
  NotebookPen,
  RefreshCcw,
  Save,
  Search,
  Shield,
  Trash2,
  Unlock,
} from "lucide-react";
import { confirm, open } from "@tauri-apps/plugin-dialog";

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
  createNote,
  deleteNote,
  getBackendMode,
  getStatus,
  importKey,
  listKeys,
  listNotes,
  lockSession,
  openFolderVault,
  openNote,
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
  recursive_scan: true,
  auto_save: false,
};

function formatFingerprint(fingerprint: string) {
  if (fingerprint.length <= 18) {
    return fingerprint;
  }
  return `${fingerprint.slice(0, 10)}...${fingerprint.slice(-8)}`;
}

function formatTimeout(seconds: number) {
  const minutes = Math.max(1, Math.round(seconds / 60));
  return `${minutes} min`;
}

function StatCard({
  label,
  value,
  caption,
}: {
  label: string;
  value: string | number;
  caption: string;
}) {
  return (
    <Card className="border-white/10 bg-card/70">
      <CardContent className="space-y-2 p-5">
        <p className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
          {label}
        </p>
        <div className="text-2xl font-semibold tracking-tight">{value}</div>
        <p className="text-sm text-muted-foreground">{caption}</p>
      </CardContent>
    </Card>
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

  async function refreshStatus() {
    setStatus(await getStatus());
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
    if (!status.auto_save || !dirty || !selectedNote || !status.session_unlocked) {
      return;
    }
    const timer = window.setTimeout(() => {
      void handleSave();
    }, 2_000);
    return () => window.clearTimeout(timer);
  }, [dirty, editorValue, selectedNote, status.auto_save, status.session_unlocked]);

  const filteredNotes = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) {
      return notes;
    }
    return notes.filter((note) => note.relative_path.toLowerCase().includes(needle));
  }, [notes, search]);

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
              filters: [{ name: "Key Files", extensions: ["asc", "gpg", "pgp", "key"] }],
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

  return (
    <div className="min-h-screen surface-grid">
      <div className="container py-6">
        <div className="space-y-6">
          <Card className="overflow-hidden border-white/10 bg-card/70">
            <CardContent className="grid gap-6 p-6 lg:grid-cols-[1.4fr_0.9fr]">
              <div className="space-y-4">
                <Badge variant="secondary" className="w-fit rounded-full px-3 py-1 text-xs">
                  Secure Workspace
                </Badge>
                <div className="space-y-2">
                  <h1 className="text-4xl font-semibold tracking-tight sm:text-5xl">
                    encryptKeeper
                  </h1>
                  <p className="max-w-2xl text-sm text-muted-foreground sm:text-base">
                    Encrypted note vault management with OpenPGP keys, session controls, and a
                    focused editor designed for desktop use.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">{backendMode === "tauri" ? "Tauri Mode" : "Mock Mode"}</Badge>
                  <Badge variant={status.session_unlocked ? "default" : "secondary"}>
                    {status.session_unlocked ? "Session unlocked" : "Session locked"}
                  </Badge>
                  <Badge variant="outline">
                    {status.vault_kind === "none" ? "No vault open" : `${status.vault_kind} vault`}
                  </Badge>
                </div>
              </div>

              <div className="flex flex-wrap items-start justify-start gap-3 lg:justify-end">
                <Button onClick={() => void handleOpenFolder()}>
                  <FolderOpen className="h-4 w-4" />
                  Open Vault
                </Button>
                <Button variant="secondary" onClick={() => void handleImportKey()}>
                  <FileKey className="h-4 w-4" />
                  Import Key
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => void handleUnlock()}
                  disabled={!status.selected_private_key || !passphrase}
                >
                  <Unlock className="h-4 w-4" />
                  Unlock
                </Button>
                <Button variant="ghost" onClick={() => void lockSession().then(refreshStatus)}>
                  <Lock className="h-4 w-4" />
                  Lock
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Vault"
              value={status.vault_path ? "Connected" : "Detached"}
              caption={status.vault_path ?? "Open a folder vault to load .gpg notes."}
            />
            <StatCard
              label="Notes"
              value={notes.length}
              caption={filteredNotes.length === notes.length ? "Visible in current view" : `${filteredNotes.length} notes match search`}
            />
            <StatCard
              label="Recipients"
              value={status.selected_recipients.length}
              caption={`${keys.filter((key) => key.has_secret).length} private keys available`}
            />
            <StatCard
              label="Timeout"
              value={formatTimeout(status.inactivity_timeout_secs)}
              caption={status.auto_save ? "Auto-save enabled" : "Manual save mode"}
            />
          </div>

          <div className="space-y-3">
            {status.session_unlocked ? (
              <Card className="border-amber-500/25 bg-amber-500/10">
                <CardContent className="flex items-center gap-3 p-4 text-sm text-amber-100">
                  <Shield className="h-4 w-4" />
                  Vault is unlocked. Plaintext is currently resident in memory for this session.
                </CardContent>
              </Card>
            ) : null}
            {backendMode === "mock" ? (
              <Card className="border-white/10 bg-muted/40">
                <CardContent className="p-4 text-sm text-muted-foreground">
                  Browser mock mode is active. This is for workflow testing only and does not use
                  real encryption or filesystem access.
                </CardContent>
              </Card>
            ) : null}
            {error ? (
              <Card className="border-red-500/25 bg-red-500/10">
                <CardContent className="p-4 text-sm text-red-100">{error}</CardContent>
              </Card>
            ) : null}
          </div>

          <div className="grid gap-4 xl:grid-cols-[360px_360px_minmax(0,1fr)]">
            <div className="space-y-4">
              <Card className="border-white/10 bg-card/70">
                <CardHeader className="space-y-2">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <CardDescription>Session</CardDescription>
                      <CardTitle>Vault controls</CardTitle>
                    </div>
                    <Badge variant="outline">{busy ?? "Idle"}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-5">
                  <div className="grid gap-3">
                    <div className="rounded-xl border border-border/70 bg-background/40 p-4">
                      <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                        Vault type
                      </div>
                      <div className="mt-2 font-medium">{status.vault_kind}</div>
                    </div>
                    <div className="rounded-xl border border-border/70 bg-background/40 p-4">
                      <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                        Active key
                      </div>
                      <div className="mt-2 font-medium">
                        {status.selected_private_key
                          ? formatFingerprint(status.selected_private_key)
                          : "No private key selected"}
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                      Unlock passphrase
                    </label>
                    <Input
                      type="password"
                      value={passphrase}
                      onChange={(event) => setPassphrase(event.target.value)}
                      placeholder="Private key passphrase"
                    />
                  </div>

                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-3 rounded-xl border border-border/70 bg-background/40 p-4">
                      <div>
                        <div className="text-sm font-medium">Recursive scan</div>
                        <div className="text-sm text-muted-foreground">
                          Include nested folders when loading notes.
                        </div>
                      </div>
                      <Switch
                        checked={status.recursive_scan}
                        onCheckedChange={(checked) =>
                          void handlePreferenceChange({ recursive_scan: checked })
                        }
                      />
                    </div>
                    <div className="flex items-center justify-between gap-3 rounded-xl border border-border/70 bg-background/40 p-4">
                      <div>
                        <div className="text-sm font-medium">Auto-save</div>
                        <div className="text-sm text-muted-foreground">
                          Write encrypted content automatically after idle.
                        </div>
                      </div>
                      <Switch
                        checked={status.auto_save}
                        onCheckedChange={(checked) =>
                          void handlePreferenceChange({ auto_save: checked })
                        }
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                      Inactivity timeout (seconds)
                    </label>
                    <Input
                      type="number"
                      min={60}
                      step={60}
                      value={status.inactivity_timeout_secs}
                      onChange={(event) =>
                        void handlePreferenceChange({
                          inactivity_timeout_secs: Number(event.target.value),
                        })
                      }
                    />
                  </div>
                </CardContent>
              </Card>

              <Card className="border-white/10 bg-card/70">
                <CardHeader className="flex flex-row items-center justify-between space-y-0">
                  <div>
                    <CardDescription>Keyring</CardDescription>
                    <CardTitle>Recipients and decrypt keys</CardTitle>
                  </div>
                  <Button variant="ghost" size="icon" onClick={() => void refreshKeys()}>
                    <RefreshCcw className="h-4 w-4" />
                  </Button>
                </CardHeader>
                <CardContent className="pt-0">
                  <ScrollArea className="h-[420px] pr-3">
                    <div className="space-y-3">
                      {keys.length === 0 ? (
                        <div className="rounded-xl border border-dashed border-border p-4 text-sm text-muted-foreground">
                          No keys imported yet.
                        </div>
                      ) : (
                        keys.map((key) => (
                          <div
                            key={key.fingerprint}
                            className="space-y-3 rounded-xl border border-border/70 bg-background/40 p-4"
                          >
                            <div className="flex items-start justify-between gap-3">
                              <div className="space-y-1">
                                <div className="font-medium">
                                  {key.user_ids[0] ?? "Unnamed key"}
                                </div>
                                <code className="text-xs text-muted-foreground">
                                  {formatFingerprint(key.fingerprint)}
                                </code>
                              </div>
                              <Badge variant={key.has_secret ? "default" : "secondary"}>
                                {key.has_secret ? "Private available" : "Public only"}
                              </Badge>
                            </div>
                            <label className="flex items-center gap-3 text-sm">
                              <input
                                type="radio"
                                name="private-key"
                                checked={key.is_selected_private}
                                disabled={!key.has_secret}
                                onChange={() => void handlePrivateKeySelection(key.fingerprint)}
                              />
                              Use for decryption
                            </label>
                            <label className="flex items-center gap-3 text-sm">
                              <input
                                type="checkbox"
                                checked={key.is_selected_recipient}
                                onChange={(event) =>
                                  void handleRecipientSelection(
                                    key.fingerprint,
                                    event.target.checked,
                                  )
                                }
                              />
                              Encrypt to recipient
                            </label>
                          </div>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            <Card className="border-white/10 bg-card/70">
              <CardHeader className="space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <CardDescription>Vault contents</CardDescription>
                    <CardTitle>Notes</CardTitle>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="ghost" size="icon" onClick={() => void refreshNotes()}>
                      <RefreshCcw className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={() => void handleCreate()}
                      disabled={status.vault_kind === "none"}
                    >
                      <NotebookPen className="h-4 w-4" />
                      New note
                    </Button>
                  </div>
                </div>

                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    className="pl-9"
                    type="search"
                    value={search}
                    placeholder="Find by name or path"
                    onChange={(event) => setSearch(event.target.value)}
                  />
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <ScrollArea className="h-[640px] pr-3">
                  <div className="space-y-3">
                    {filteredNotes.length === 0 ? (
                      <div className="rounded-xl border border-dashed border-border p-4 text-sm text-muted-foreground">
                        No notes match the current filter.
                      </div>
                    ) : (
                      filteredNotes.map((note) => (
                        <button
                          key={note.id}
                          className={cn(
                            "w-full rounded-xl border p-4 text-left transition-colors",
                            selectedNote?.id === note.id
                              ? "border-primary/40 bg-primary/10"
                              : "border-border/70 bg-background/40 hover:bg-accent",
                          )}
                          onClick={() => void handleSelectNote(note)}
                        >
                          <div className="font-medium">{note.name}</div>
                          <div className="mt-1 text-sm text-muted-foreground">
                            {note.relative_path}
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card className="border-white/10 bg-card/70">
              <CardHeader className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <CardDescription>Editor</CardDescription>
                    <CardTitle>{selectedNote?.relative_path ?? "No note selected"}</CardTitle>
                  </div>
                  <Badge variant={dirty ? "default" : "outline"}>
                    {dirty ? "Unsaved changes" : busy ?? "Ready"}
                  </Badge>
                </div>

                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => void handleSave()} disabled={!dirty || !selectedNote}>
                    <Save className="h-4 w-4" />
                    Save
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => void handleRename()}
                    disabled={!selectedNote}
                  >
                    Rename
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => void handleDelete()}
                    disabled={!selectedNote}
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <Textarea
                  className="min-h-[640px] rounded-2xl bg-background/70 font-mono text-sm leading-7"
                  value={editorValue}
                  placeholder="Open or create a .gpg note to edit plaintext markdown-friendly text here."
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
