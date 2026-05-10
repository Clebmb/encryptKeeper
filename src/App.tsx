import { useEffect, useMemo, useRef, useState, type CSSProperties, type DragEvent as ReactDragEvent } from "react";
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
  Clipboard,
  Copy,
  Files,
  FolderPlus,
  FileKey,
  FolderOpen,
  GripVertical,
  KeyRound,
  Lock,
  NotebookPen,
  Pencil,
  Pin,
  Plus,
  RefreshCcw,
  Save,
  Search,
  Shield,
  Trash2,
  Upload,
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
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  addSubkey,
  certifyKey,
  changeKeyPassphrase,
  createNote,
  createKey,
  createX509Certificate,
  decryptCmsFiles,
  decryptFiles,
  deleteNote,
  encryptCmsFiles,
  encryptFiles,
  exportRevocationCertificate,
  exportOwnertrust,
  exportPrivateKey,
  exportPublicKey,
  exportX509Certificate,
  exportX509SecretKeyP12,
  exportX509SecretKeyP8,
  createSmartcardKeyStubs,
  fetchSmartcardPublicKey,
  factoryResetSmartcard,
  generateSmartcardKey,
  changeX509Passphrase,
  deleteX509Certificate,
  exportX509Trustlist,
  getX509CertificateChain,
  getPinnedKeySettings,
  getBackendMode,
  getKeyDetails,
  changeSmartcardPin,
  importX509Crl,
  setX509TrustRoot,
  importKeyFromKeyserver,
  getSmartcardStatus,
  getStatus,
  importKey,
  importKeyText,
  importX509Certificate,
  importX509CertificateText,
  importOwnertrust,
  importX509Trustlist,
  inspectNoteEncryption,
  listKeys,
  learnX509Card,
  listX509Certificates,
  listNotes,
  lockSession,
  lookupKey,
  openArchiveVault,
  openFolderVault,
  publishKeyToKeyserver,
  openNote,
  openNoteWithPassword,
  previewPgpBlock,
  refreshAllKeysFromKeyserver,
  refreshKeyFromKeyserver,
  restartSmartcardService,
  refreshNotesFromVault,
  resolveClipboardNoteContent,
  removeKey,
  renameNote,
  saveNote,
  saveNoteWithPassword,
  searchKeyserver,
  savePinnedKeySettings,
  selectPrivateKey,
  setKeyExpiry,
  setKeyOwnertrust,
  setRecipients,
  moveSecretKeyToSmartcard,
  signCmsFiles,
  signFiles,
  unlockSession,
  updatePreferences,
  verifyCmsFileSignature,
  verifyClipboardSignature,
  verifyFileSignature,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { normalizeNoteName } from "@/lib/noteName";
import type {
  FileOperationResult,
  ImportKeyResult,
  KeyActionResult,
  KeyDetails,
  KeySummary,
  KeyserverSearchResult,
  NoteEncryptionStatus,
  NoteSignatureStatus,
  NoteSummary,
  SmartcardStatus,
  X509CertificateSummary,
  SessionStatus,
} from "@/types";

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

const defaultNoteEncryptionStatus: NoteEncryptionStatus = {
  recipients: [],
  can_decrypt_with_selected_key: false,
  matches_selected_recipients: true,
  signature: {
    state: "unknown",
    signer_key_id: null,
    signer_fingerprint: null,
    signer_label: null,
    summary: "Open a note to verify its signature.",
  },
};

const KEY_ORDER_STORAGE_KEY = "encryptkeeper.key-order";
const HIDE_NOTE_NAMES_ON_LOCK_STORAGE_KEY = "encryptkeeper.hide-note-names-on-lock";
const USE_CLIPBOARD_STORAGE_KEY = "encryptkeeper.use-clipboard";
const AUTO_SHOW_RECIPIENTS_STORAGE_KEY = "encryptkeeper.auto-show-recipients";
const AUTO_SHOW_PGP_BLOCK_STORAGE_KEY = "encryptkeeper.auto-show-pgp-block";
const SHOW_RECENT_HISTORY_STORAGE_KEY = "encryptkeeper.show-recent-history";
const SAVED_VAULTS_STORAGE_KEY = "encryptkeeper.saved-vaults";
const PINNED_VAULT_PATH_STORAGE_KEY = "encryptkeeper.pinned-vault-path";
const WINDOW_SIZE_STORAGE_KEY = "encryptkeeper.window-size";
const ACTIVITY_LOG_STORAGE_KEY = "encryptkeeper.activity-log";
const STARTUP_WINDOW_SIZE = {
  width: 1040,
  height: 560,
};

const defaultSmartcardStatus: SmartcardStatus = {
  available: false,
  summary: "No smartcard or hardware token detected.",
  reader: null,
  serial_number: null,
  application_id: null,
  manufacturer: null,
  cardholder: null,
  signature_key: null,
  encryption_key: null,
  authentication_key: null,
};

const smartcardSlotOptions = [
  { value: "OPENPGP.1", label: "Signing slot" },
  { value: "OPENPGP.2", label: "Encryption slot" },
  { value: "OPENPGP.3", label: "Authentication slot" },
] as const;

const smartcardAlgorithmOptions = [
  { value: "rsa2048", label: "RSA 2048" },
  { value: "rsa3072", label: "RSA 3072" },
  { value: "rsa4096", label: "RSA 4096" },
  { value: "ed25519", label: "Ed25519" },
  { value: "cv25519", label: "Curve25519" },
] as const;

function defaultSmartcardSlotForCapabilities(capabilities: string[]) {
  if (capabilities.includes("Encrypt")) {
    return "OPENPGP.2";
  }
  if (capabilities.includes("Authenticate")) {
    return "OPENPGP.3";
  }
  return "OPENPGP.1";
}

function defaultX509ExpiryDate(): string {
  const nextYear = new Date();
  nextYear.setFullYear(nextYear.getFullYear() + 1);
  return nextYear.toISOString().slice(0, 10);
}

interface SavedVault {
  path: string;
  label: string;
}

interface StoredWindowSize {
  width: number;
  height: number;
}

type AppTab = "vault" | "files" | "keyring";
type ActivityKind = "note" | "file" | "key" | "session";
type FileCryptoMode = "openpgp" | "smime";

interface ActivityItem {
  id: string;
  at: number;
  kind: ActivityKind;
  title: string;
  detail: string;
}

const ownertrustOptions = [
  { value: "undefined", label: "Unknown" },
  { value: "never", label: "Never" },
  { value: "marginal", label: "Marginal" },
  { value: "full", label: "Full" },
  { value: "ultimate", label: "Ultimate" },
] as const;

const subkeyPresetOptions = [
  {
    value: "encrypt",
    label: "Encryption",
    algorithm: "cv25519",
    usage: "encr",
  },
  {
    value: "sign",
    label: "Signing",
    algorithm: "ed25519",
    usage: "sign",
  },
  {
    value: "auth",
    label: "Authentication",
    algorithm: "ed25519",
    usage: "auth",
  },
] as const;

function formatTimestamp(epoch: number | null) {
  if (!epoch) {
    return "Never";
  }
  return new Date(epoch * 1000).toLocaleDateString();
}

function formatDateInput(epoch: number | null) {
  if (!epoch) {
    return "never";
  }
  return new Date(epoch * 1000).toISOString().slice(0, 10);
}

function ownertrustValueFromLabel(value: string) {
  const normalized = value.trim().toLowerCase();
  if (normalized.includes("ultimate")) {
    return "ultimate";
  }
  if (normalized.includes("full")) {
    return "full";
  }
  if (normalized.includes("marginal")) {
    return "marginal";
  }
  if (normalized.includes("never")) {
    return "never";
  }
  return "undefined";
}

function keyRoleSummary(key: KeySummary) {
  if (key.is_selected_private) {
    return "Active private key for decrypt, sign, and key-management actions.";
  }
  if (key.is_selected_recipient) {
    return "Selected recipient for new encrypted notes and file operations.";
  }
  if (key.has_secret) {
    return "Private key is available locally, but it is not the active decrypt/sign key.";
  }
  return "Public key only. Use it for recipients, trust decisions, or certification review.";
}

function keyTrustSummary(key: KeySummary) {
  const trust = key.trust.trim().toLowerCase();
  if (trust.includes("ultimate")) {
    return "This key is fully trusted on this device.";
  }
  if (trust.includes("full")) {
    return "This key is strongly trusted, but not marked ultimate.";
  }
  if (trust.includes("marginal")) {
    return "This key has limited trust. Verify identity before relying on signatures.";
  }
  if (trust.includes("never")) {
    return "This key is explicitly untrusted on this device.";
  }
  if (trust.includes("expired")) {
    return "This key is expired. Refresh it or extend the expiration before use.";
  }
  if (trust.includes("revoked")) {
    return "This key is revoked and should not be used.";
  }
  return "Trust has not been established yet. Review certifications and ownertrust.";
}

function keyStatusWarnings(key: KeySummary) {
  const warnings: string[] = [];
  if (key.expires_at && key.expires_at * 1000 < Date.now()) {
    warnings.push("The key is expired.");
  }
  if (key.is_selected_private && !key.has_secret) {
    warnings.push("The active private-key selection no longer has a local secret key.");
  }
  if (key.is_selected_recipient && !key.capabilities.includes("Encrypt")) {
    warnings.push("This recipient key does not advertise encryption capability.");
  }
  if (!key.has_secret && key.capabilities.includes("Sign")) {
    warnings.push("Only public material is available locally, so signing is not possible.");
  }
  return warnings;
}

function x509ValidationSummary(validity: string, report: string) {
  const normalizedValidity = validity.trim().toLowerCase();
  const normalizedReport = report.trim().toLowerCase();

  if (!normalizedReport) {
    return "Validation details are not available yet. Run validation or refresh the certificate view.";
  }
  if (normalizedReport.includes("revoked")) {
    return "Validation reports this certificate as revoked. Do not rely on it.";
  }
  if (normalizedReport.includes("expired")) {
    return "Validation reports this certificate as expired. Renew or replace it before use.";
  }
  if (normalizedReport.includes("no issuer") || normalizedReport.includes("missing issuer")) {
    return "Validation could not build a complete issuer chain for this certificate.";
  }
  if (normalizedReport.includes("crl") && normalizedReport.includes("error")) {
    return "Validation ran, but revocation status could not be confirmed cleanly.";
  }
  if (
    normalizedReport.includes("certificate is good")
    || normalizedReport.includes("root certificate is good")
    || normalizedReport.includes("trusted")
  ) {
    return "Validation completed without an obvious trust or revocation failure in the reported chain.";
  }
  if (normalizedValidity.includes("full") || normalizedValidity.includes("ultimate")) {
    return "This certificate currently looks usable, but review the reported chain before relying on it.";
  }
  if (normalizedValidity.includes("expired")) {
    return "This certificate is expired based on the local certificate store state.";
  }
  if (normalizedValidity.includes("revoked")) {
    return "This certificate is marked revoked in the local certificate store.";
  }
  return "Validation completed, but the chain report should be reviewed for issuer and revocation details.";
}

function formatActivityTime(epochMs: number) {
  return new Date(epochMs).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function activityBadgeVariant(kind: ActivityKind) {
  if (kind === "key") {
    return "default";
  }
  if (kind === "file") {
    return "secondary";
  }
  return "outline";
}

function filePathLabel(path: string) {
  const segments = path.split(/[/\\]/).filter(Boolean);
  return segments[segments.length - 1] || path;
}

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

function loadHideNoteNamesOnLock() {
  if (typeof window === "undefined") {
    return false;
  }

  try {
    return window.localStorage.getItem(HIDE_NOTE_NAMES_ON_LOCK_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

function loadStoredBoolean(key: string, fallback = false) {
  if (typeof window === "undefined") {
    return fallback;
  }

  try {
    const value = window.localStorage.getItem(key);
    return value === null ? fallback : value === "true";
  } catch {
    return fallback;
  }
}

function loadStoredVaults() {
  if (typeof window === "undefined") {
    return [] as SavedVault[];
  }

  try {
    const raw = window.localStorage.getItem(SAVED_VAULTS_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(parsed)) {
      return [] as SavedVault[];
    }

    return parsed
      .filter(
        (value): value is SavedVault =>
          typeof value === "object" &&
          value !== null &&
          typeof value.path === "string" &&
          typeof value.label === "string",
      )
      .map((vault) => ({ path: vault.path, label: vault.label.trim() || deriveVaultLabel(vault.path) }))
      .sort((left, right) => left.label.localeCompare(right.label));
  } catch {
    return [] as SavedVault[];
  }
}

function loadStoredPinnedVaultPath() {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    const value = window.localStorage.getItem(PINNED_VAULT_PATH_STORAGE_KEY);
    return value && value.trim() ? value : null;
  } catch {
    return null;
  }
}

function loadStoredWindowSize() {
  if (typeof window === "undefined") {
    return null as StoredWindowSize | null;
  }

  try {
    const raw = window.localStorage.getItem(WINDOW_SIZE_STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as Partial<StoredWindowSize>) : null;
    if (
      !parsed ||
      typeof parsed.width !== "number" ||
      typeof parsed.height !== "number" ||
      parsed.width <= 0 ||
      parsed.height <= 0
    ) {
      return null;
    }

    return {
      width: parsed.width,
      height: parsed.height,
    };
  } catch {
    return null;
  }
}

function loadActivityLog() {
  if (typeof window === "undefined") {
    return [] as ActivityItem[];
  }

  try {
    const raw = window.localStorage.getItem(ACTIVITY_LOG_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(parsed)) {
      return [] as ActivityItem[];
    }

    return parsed.filter(
      (value): value is ActivityItem =>
        typeof value === "object" &&
        value !== null &&
        typeof value.id === "string" &&
        typeof value.at === "number" &&
        typeof value.kind === "string" &&
        typeof value.title === "string" &&
        typeof value.detail === "string",
    );
  } catch {
    return [] as ActivityItem[];
  }
}

function deriveVaultLabel(path: string) {
  const segments = path.split(/[/\\]/).filter(Boolean);
  return segments[segments.length - 1] || path;
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

function isEditableTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.isContentEditable) {
    return true;
  }

  return Boolean(target.closest("input, textarea, [contenteditable='true']"));
}

function isPgpMessageBlock(value: string) {
  return (
    value.includes("-----BEGIN PGP MESSAGE-----") && value.includes("-----END PGP MESSAGE-----")
  );
}

function isPgpSignedMessageBlock(value: string) {
  return (
    value.includes("-----BEGIN PGP SIGNED MESSAGE-----") &&
    value.includes("-----BEGIN PGP SIGNATURE-----") &&
    value.includes("-----END PGP SIGNATURE-----")
  );
}

function isPgpSignatureBlock(value: string) {
  return (
    value.includes("-----BEGIN PGP SIGNATURE-----") &&
    value.includes("-----END PGP SIGNATURE-----")
  );
}

function isPgpKeyBlock(value: string) {
  return (
    (value.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----") &&
      value.includes("-----END PGP PUBLIC KEY BLOCK-----")) ||
    (value.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----") &&
      value.includes("-----END PGP PRIVATE KEY BLOCK-----"))
  );
}

function signatureBadgeVariant(state: NoteEncryptionStatus["signature"]["state"]) {
  if (state === "good") {
    return "default";
  }
  if (state === "bad" || state === "unknown") {
    return "secondary";
  }
  return "outline";
}

interface SortableKeyCardProps {
  keyItem: KeySummary;
  isPrivatePinned: boolean;
  isRecipientPinned: boolean;
  onPrivateKeySelection: (fingerprint: string) => void;
  onRecipientSelection: (fingerprint: string, checked: boolean) => void;
  onTogglePrivatePin: (key: KeySummary) => void;
  onToggleRecipientPin: (key: KeySummary) => void;
  onExportPublic: (key: KeySummary) => void;
  onOpenExportDialog: (key: KeySummary, mode: "private" | "both") => void;
  onRemoveKey: (key: KeySummary) => void;
}

function KeyIdentityLabel({ value }: { value: string }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const textRef = useRef<HTMLSpanElement | null>(null);
  const [scrollDistance, setScrollDistance] = useState(0);

  useEffect(() => {
    function measure() {
      const container = containerRef.current;
      const text = textRef.current;
      if (!container || !text) {
        return;
      }

      const nextDistance = Math.max(0, text.scrollWidth - container.clientWidth);
      setScrollDistance(nextDistance);
    }

    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [value]);

  return (
    <div
      ref={containerRef}
      className="key-identity-marquee overflow-hidden text-sm font-medium"
      title={value}
    >
      <span
        ref={textRef}
        data-overflow={scrollDistance > 0}
        className="key-identity-text inline-block whitespace-nowrap"
        style={
          {
            "--key-scroll-distance": `${scrollDistance}px`,
            "--key-scroll-duration": `${Math.max(4, scrollDistance / 36)}s`,
          } as CSSProperties
        }
      >
        {value}
      </span>
    </div>
  );
}

function SortableKeyCard({
  keyItem,
  isPrivatePinned,
  isRecipientPinned,
  onPrivateKeySelection,
  onRecipientSelection,
  onTogglePrivatePin,
  onToggleRecipientPin,
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
            <KeyIdentityLabel value={keyItem.user_ids[0] ?? "Unnamed key"} />
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
          <div className="flex items-center justify-between gap-2">
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
            <Button
              size="icon"
              variant="ghost"
              className="size-7 shrink-0"
              disabled={!keyItem.has_secret}
              onClick={() => void onTogglePrivatePin(keyItem)}
              aria-label={isPrivatePinned ? "Unpin decrypt setting" : "Pin decrypt setting"}
              title={isPrivatePinned ? "Unpin decrypt setting" : "Pin decrypt setting"}
            >
              <Pin className={cn("h-3.5 w-3.5", isPrivatePinned && "fill-white text-white")} />
            </Button>
          </div>
          <div className="flex items-center justify-between gap-2">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={keyItem.is_selected_recipient}
                onChange={(event) => void onRecipientSelection(keyItem.fingerprint, event.target.checked)}
              />
              Encrypt to this key
            </label>
            <Button
              size="icon"
              variant="ghost"
              className="size-7 shrink-0"
              onClick={() => void onToggleRecipientPin(keyItem)}
              aria-label={isRecipientPinned ? "Unpin recipient setting" : "Pin recipient setting"}
              title={isRecipientPinned ? "Unpin recipient setting" : "Pin recipient setting"}
            >
              <Pin className={cn("h-3.5 w-3.5", isRecipientPinned && "fill-white text-white")} />
            </Button>
          </div>
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
  const [activeTab, setActiveTab] = useState<AppTab>("vault");
  const [status, setStatus] = useState<SessionStatus>(defaultStatus);
  const [keys, setKeys] = useState<KeySummary[]>([]);
  const [selectedKeyFingerprint, setSelectedKeyFingerprint] = useState<string | null>(null);
  const [selectedKeyDetails, setSelectedKeyDetails] = useState<KeyDetails | null>(null);
  const [isLoadingKeyDetails, setIsLoadingKeyDetails] = useState(false);
  const [smartcardStatus, setSmartcardStatus] = useState<SmartcardStatus>(defaultSmartcardStatus);
  const [x509Certificates, setX509Certificates] = useState<X509CertificateSummary[]>([]);
  const [selectedX509Fingerprint, setSelectedX509Fingerprint] = useState<string | null>(null);
  const [selectedX509Chain, setSelectedX509Chain] = useState("");
  const [selectedX509SignerFingerprint, setSelectedX509SignerFingerprint] = useState<string | null>(null);
  const [selectedX509Recipients, setSelectedX509Recipients] = useState<string[]>([]);
  const [isLoadingSmartcardStatus, setIsLoadingSmartcardStatus] = useState(false);
  const [isSmartcardGenerateDialogOpen, setIsSmartcardGenerateDialogOpen] = useState(false);
  const [smartcardGenerateSlot, setSmartcardGenerateSlot] =
    useState<(typeof smartcardSlotOptions)[number]["value"]>("OPENPGP.1");
  const [smartcardGenerateAlgorithm, setSmartcardGenerateAlgorithm] =
    useState<(typeof smartcardAlgorithmOptions)[number]["value"]>("rsa3072");
  const [smartcardGenerateForce, setSmartcardGenerateForce] = useState(false);
  const [isSmartcardStoreDialogOpen, setIsSmartcardStoreDialogOpen] = useState(false);
  const [smartcardStoreFingerprint, setSmartcardStoreFingerprint] = useState("");
  const [smartcardStoreSlot, setSmartcardStoreSlot] =
    useState<(typeof smartcardSlotOptions)[number]["value"]>("OPENPGP.1");
  const [smartcardStoreForce, setSmartcardStoreForce] = useState(false);
  const [isCreateX509DialogOpen, setIsCreateX509DialogOpen] = useState(false);
  const [isPasteX509DialogOpen, setIsPasteX509DialogOpen] = useState(false);
  const [pastedX509CertificateText, setPastedX509CertificateText] = useState("");
  const [newX509CommonName, setNewX509CommonName] = useState("");
  const [newX509Organization, setNewX509Organization] = useState("");
  const [newX509Email, setNewX509Email] = useState("");
  const [newX509Expiry, setNewX509Expiry] = useState(() => defaultX509ExpiryDate());
  const [newX509Passphrase, setNewX509Passphrase] = useState("");
  const [isCreatingX509Certificate, setIsCreatingX509Certificate] = useState(false);
  const [keySearch, setKeySearch] = useState("");
  const [notes, setNotes] = useState<NoteSummary[]>([]);
  const [selectedFilePaths, setSelectedFilePaths] = useState<string[]>([]);
  const [fileOutputDir, setFileOutputDir] = useState("");
  const [fileCryptoMode, setFileCryptoMode] = useState<FileCryptoMode>("openpgp");
  const [fileOperationResults, setFileOperationResults] = useState<FileOperationResult[]>([]);
  const [verifyInputPath, setVerifyInputPath] = useState("");
  const [verifySignaturePath, setVerifySignaturePath] = useState("");
  const [fileVerificationStatus, setFileVerificationStatus] = useState<NoteSignatureStatus | null>(null);
  const [isFileDropActive, setIsFileDropActive] = useState(false);
  const [selectedNote, setSelectedNote] = useState<NoteSummary | null>(null);
  const [editorValue, setEditorValue] = useState("");
  const [search, setSearch] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [timeoutMinutesInput, setTimeoutMinutesInput] = useState("");
  const [countdownSecs, setCountdownSecs] = useState<number | null>(null);
  const [isPgpPreviewOpen, setIsPgpPreviewOpen] = useState(false);
  const [pgpPreview, setPgpPreview] = useState("");
  const [pgpPreviewError, setPgpPreviewError] = useState<string | null>(null);
  const [pgpPreviewBusy, setPgpPreviewBusy] = useState(false);
  const [noteEncryptionStatus, setNoteEncryptionStatus] = useState<NoteEncryptionStatus>(
    defaultNoteEncryptionStatus,
  );
  const [showRecipients, setShowRecipients] = useState(true);
  const [hideNoteNamesOnLock, setHideNoteNamesOnLock] = useState(() => loadHideNoteNamesOnLock());
  const [useClipboard, setUseClipboard] = useState(() =>
    loadStoredBoolean(USE_CLIPBOARD_STORAGE_KEY, true),
  );
  const [autoShowRecipients, setAutoShowRecipients] = useState(() =>
    loadStoredBoolean(AUTO_SHOW_RECIPIENTS_STORAGE_KEY, false),
  );
  const [autoShowPgpBlock, setAutoShowPgpBlock] = useState(() =>
    loadStoredBoolean(AUTO_SHOW_PGP_BLOCK_STORAGE_KEY, false),
  );
  const [showRecentHistory, setShowRecentHistory] = useState(() =>
    loadStoredBoolean(SHOW_RECENT_HISTORY_STORAGE_KEY, true),
  );
  const [isRecentHistoryOpen, setIsRecentHistoryOpen] = useState(false);
  const [useSignature, setUseSignature] = useState(false);
  const [isCreateKeyOpen, setIsCreateKeyOpen] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyEmail, setNewKeyEmail] = useState("");
  const [newKeyPassphrase, setNewKeyPassphrase] = useState("");
  const [isCreatingKey, setIsCreatingKey] = useState(false);
  const [savedVaults, setSavedVaults] = useState<SavedVault[]>(() => loadStoredVaults());
  const [pinnedVaultPath, setPinnedVaultPath] = useState<string | null>(() => loadStoredPinnedVaultPath());
  const [isVaultSaveDialogOpen, setIsVaultSaveDialogOpen] = useState(false);
  const [vaultPathInput, setVaultPathInput] = useState("");
  const [vaultLabelInput, setVaultLabelInput] = useState("");
  const [isExportDialogOpen, setIsExportDialogOpen] = useState(false);
  const [exportMode, setExportMode] = useState<"private" | "both">("private");
  const [exportTargetKey, setExportTargetKey] = useState<KeySummary | null>(null);
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [isKeyToolsOpen, setIsKeyToolsOpen] = useState(false);
  const [isLookupDialogOpen, setIsLookupDialogOpen] = useState(false);
  const [lookupQuery, setLookupQuery] = useState("");
  const [keyserverResults, setKeyserverResults] = useState<KeyserverSearchResult[]>([]);
  const [isSearchingKeyserver, setIsSearchingKeyserver] = useState(false);
  const [keyExpiryInput, setKeyExpiryInput] = useState("");
  const [ownertrustInput, setOwnertrustInput] = useState("undefined");
  const [subkeyPreset, setSubkeyPreset] = useState<(typeof subkeyPresetOptions)[number]["value"]>("encrypt");
  const [subkeyExpireInput, setSubkeyExpireInput] = useState("1y");
  const [newKeyPassphraseInput, setNewKeyPassphraseInput] = useState("");
  const [confirmKeyPassphraseInput, setConfirmKeyPassphraseInput] = useState("");
  const [revocationPassphrase, setRevocationPassphrase] = useState("");
  const [latestImportResult, setLatestImportResult] = useState<ImportKeyResult | null>(null);
  const [latestKeyAction, setLatestKeyAction] = useState<KeyActionResult | null>(null);
  const [activityLog, setActivityLog] = useState<ActivityItem[]>(() => loadActivityLog());
  const [keyOrder, setKeyOrder] = useState<string[]>(() => loadStoredKeyOrder());
  const [pinnedPrivateKey, setPinnedPrivateKey] = useState<string | null>(null);
  const [pinnedRecipients, setPinnedRecipients] = useState<string[]>([]);
  const wasUnlockedRef = useRef(status.session_unlocked);
  const previewRequestRef = useRef(0);
  const createKeyInFlightRef = useRef(false);
  const applyingPinnedSettingsRef = useRef(false);
  const autoOpenedPinnedVaultRef = useRef(false);
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
    return nextStatus;
  }

  async function refreshKeys() {
    setKeys(await listKeys());
  }

  async function refreshSmartcardStatus() {
    setIsLoadingSmartcardStatus(true);
    try {
      const next = await getSmartcardStatus();
      setSmartcardStatus(next);
      return next;
    } finally {
      setIsLoadingSmartcardStatus(false);
    }
  }

  async function refreshX509Certificates() {
    const certificates = await listX509Certificates();
    setX509Certificates(certificates);
    setSelectedX509Fingerprint((current) => {
      if (current && certificates.some((certificate) => certificate.fingerprint === current)) {
        return current;
      }
      return certificates[0]?.fingerprint ?? null;
    });
  }

  async function refreshNotes() {
    setNotes(await listNotes());
  }

  async function handleRefreshNotes() {
    await withBusy("Refreshing notes...", async () => {
      const nextNotes = await refreshNotesFromVault();
      setNotes(nextNotes);
      if (selectedNote && !nextNotes.some((note) => note.id === selectedNote.id)) {
        setSelectedNote(null);
        setEditorValue("");
        setDirty(false);
        setShowRecipients(false);
        setIsPgpPreviewOpen(false);
        setNoteEncryptionStatus(defaultNoteEncryptionStatus);
      }
    });
  }

  async function refreshNoteEncryption(noteId: string) {
    setNoteEncryptionStatus(await inspectNoteEncryption(noteId));
  }

  useEffect(() => {
    void (async () => {
      setBusy("Loading workspace...");
      try {
        const [pinnedSettings, nextStatus] = await Promise.all([
          getPinnedKeySettings(),
          refreshStatus(),
          refreshKeys(),
          refreshX509Certificates(),
          refreshSmartcardStatus(),
          refreshNotes(),
        ]);
        setPinnedPrivateKey(pinnedSettings.private_key_fingerprint);
        setPinnedRecipients(pinnedSettings.recipient_fingerprints);

        if (!autoOpenedPinnedVaultRef.current && pinnedVaultPath) {
          autoOpenedPinnedVaultRef.current = true;
          await openVaultPath(pinnedVaultPath, "Opening pinned vault...", nextStatus.recursive_scan);
        }
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
    if (keys.length === 0) {
      setSelectedKeyFingerprint(null);
      setSelectedKeyDetails(null);
      return;
    }

    setSelectedKeyFingerprint((current) => {
      if (current && keys.some((key) => key.fingerprint === current)) {
        return current;
      }
      return keys[0]?.fingerprint ?? null;
    });
  }, [keys]);

  useEffect(() => {
    if (!selectedKeyFingerprint) {
      setSelectedKeyDetails(null);
      return;
    }

    setIsLoadingKeyDetails(true);
    void getKeyDetails(selectedKeyFingerprint)
      .then((details) => setSelectedKeyDetails(details))
      .catch((cause) => setError(cause instanceof Error ? cause.message : String(cause)))
      .finally(() => setIsLoadingKeyDetails(false));
  }, [keys, selectedKeyFingerprint]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(KEY_ORDER_STORAGE_KEY, JSON.stringify(keyOrder));
  }, [keyOrder]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(SAVED_VAULTS_STORAGE_KEY, JSON.stringify(savedVaults));
  }, [savedVaults]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(ACTIVITY_LOG_STORAGE_KEY, JSON.stringify(activityLog));
  }, [activityLog]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    if (pinnedVaultPath) {
      window.localStorage.setItem(PINNED_VAULT_PATH_STORAGE_KEY, pinnedVaultPath);
      return;
    }
    window.localStorage.removeItem(PINNED_VAULT_PATH_STORAGE_KEY);
  }, [pinnedVaultPath]);

  useEffect(() => {
    if (!selectedX509Fingerprint) {
      setSelectedX509Chain("");
      return;
    }

    void getX509CertificateChain(selectedX509Fingerprint)
      .then((chain) => setSelectedX509Chain(chain))
      .catch((cause) => setError(cause instanceof Error ? cause.message : String(cause)));
  }, [selectedX509Fingerprint]);

  useEffect(() => {
    if (backendMode !== "tauri") {
      return;
    }

    let unlisten: (() => void) | undefined;

    void (async () => {
      const { LogicalSize, PhysicalPosition, currentMonitor, getCurrentWindow, primaryMonitor } =
        await import("@tauri-apps/api/window");
      const appWindow = getCurrentWindow();

      try {
        await appWindow.setSize(new LogicalSize(STARTUP_WINDOW_SIZE.width, STARTUP_WINDOW_SIZE.height));

        const monitor = (await currentMonitor()) ?? (await primaryMonitor());
        if (monitor) {
          const size = await appWindow.outerSize();
          const left = monitor.position.x + Math.max(0, Math.round((monitor.size.width - size.width) / 2));
          const centeredTop = monitor.position.y + Math.round((monitor.size.height - size.height) / 2);
          const top = Math.max(monitor.position.y, centeredTop);
          await appWindow.setPosition(new PhysicalPosition(left, top));
        }
      } finally {
        await appWindow.show();
        await appWindow.setFocus();
      }

      unlisten = await appWindow.onResized(async () => {
        const size = await appWindow.outerSize();
        window.localStorage.setItem(
          WINDOW_SIZE_STORAGE_KEY,
          JSON.stringify({ width: size.width, height: size.height }),
        );
      });
    })();

    return () => {
      unlisten?.();
    };
  }, [backendMode]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(
      HIDE_NOTE_NAMES_ON_LOCK_STORAGE_KEY,
      hideNoteNamesOnLock ? "true" : "false",
    );
  }, [hideNoteNamesOnLock]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(USE_CLIPBOARD_STORAGE_KEY, useClipboard ? "true" : "false");
  }, [useClipboard]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(
      AUTO_SHOW_RECIPIENTS_STORAGE_KEY,
      autoShowRecipients ? "true" : "false",
    );
  }, [autoShowRecipients]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(
      AUTO_SHOW_PGP_BLOCK_STORAGE_KEY,
      autoShowPgpBlock ? "true" : "false",
    );
  }, [autoShowPgpBlock]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    try {
      window.localStorage.setItem(
        SHOW_RECENT_HISTORY_STORAGE_KEY,
        showRecentHistory ? "true" : "false",
      );
    } catch {
      // Ignore storage errors and keep the in-memory preference.
    }
  }, [showRecentHistory]);

  useEffect(() => {
    if (!showRecentHistory) {
      setIsRecentHistoryOpen(false);
    }
  }, [showRecentHistory]);

  useEffect(() => {
    const availableFingerprints = new Set(keys.map((key) => key.fingerprint));
    const sanitizedPinnedPrivate =
      pinnedPrivateKey && availableFingerprints.has(pinnedPrivateKey) ? pinnedPrivateKey : null;
    const sanitizedPinnedRecipients = pinnedRecipients.filter((fingerprint) =>
      availableFingerprints.has(fingerprint),
    );

    if (sanitizedPinnedPrivate !== pinnedPrivateKey) {
      setPinnedPrivateKey(sanitizedPinnedPrivate);
      return;
    }

    if (
      sanitizedPinnedRecipients.length !== pinnedRecipients.length ||
      sanitizedPinnedRecipients.some((fingerprint, index) => fingerprint !== pinnedRecipients[index])
    ) {
      setPinnedRecipients(sanitizedPinnedRecipients);
      return;
    }

    if (keys.length === 0) {
      return;
    }

    const selectedPrivate = keys.find((key) => key.is_selected_private)?.fingerprint ?? null;
    const selectedRecipients = keys
      .filter((key) => key.is_selected_recipient)
      .map((key) => key.fingerprint);

    const missingPinnedPrivate =
      Boolean(sanitizedPinnedPrivate) && selectedPrivate !== sanitizedPinnedPrivate;
    const missingPinnedRecipients = sanitizedPinnedRecipients.filter(
      (fingerprint) => !selectedRecipients.includes(fingerprint),
    );

    if (!missingPinnedPrivate && missingPinnedRecipients.length === 0) {
      void savePinnedKeySettings(sanitizedPinnedPrivate, sanitizedPinnedRecipients).catch(() => undefined);
      return;
    }

    void (async () => {
      try {
        if (applyingPinnedSettingsRef.current) {
          return;
        }
        applyingPinnedSettingsRef.current = true;

        if (sanitizedPinnedPrivate && selectedPrivate !== sanitizedPinnedPrivate) {
          await selectPrivateKey(sanitizedPinnedPrivate);
        }

        if (missingPinnedRecipients.length > 0) {
          const nextRecipients = [...new Set([...selectedRecipients, ...sanitizedPinnedRecipients])];
          await setRecipients(nextRecipients);
        }

        await Promise.all([refreshKeys(), refreshStatus()]);
      } catch {
        return;
      } finally {
        applyingPinnedSettingsRef.current = false;
      }
    })();
  }, [keys, pinnedPrivateKey, pinnedRecipients]);

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
      setNoteEncryptionStatus(defaultNoteEncryptionStatus);
      setShowRecipients(false);
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
      void previewPgpBlock(editorValue, useSignature || status.selected_recipients.length === 0)
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
  }, [
    editorValue,
    isPgpPreviewOpen,
    selectedNote,
    status.session_unlocked,
    status.selected_recipients,
    useSignature,
  ]);

  useEffect(() => {
    if (!useClipboard) {
      return;
    }

    function handlePaste(event: ClipboardEvent) {
      if (isEditableTarget(event.target)) {
        return;
      }

      const clipboardText = event.clipboardData?.getData("text") ?? "";
      const trimmed = clipboardText.trim();
      if (!trimmed) {
        return;
      }

      const isRecognizedClipboardPayload =
        isPgpKeyBlock(trimmed) ||
        isPgpSignedMessageBlock(trimmed) ||
        isPgpSignatureBlock(trimmed) ||
        (isPgpMessageBlock(trimmed) && status.session_unlocked && Boolean(status.selected_private_key));
      if (!isRecognizedClipboardPayload) {
        return;
      }

      event.preventDefault();

      void (async () => {
        try {
          await handleClipboardPasteAction(trimmed);
        } catch (cause) {
          setError(cause instanceof Error ? cause.message : String(cause));
        }
      })();
    }

    document.addEventListener("paste", handlePaste);
    return () => document.removeEventListener("paste", handlePaste);
  }, [backendMode, busy, status.selected_private_key, status.session_unlocked, useClipboard]);

  const filteredNotes = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) {
      return notes;
    }
    return notes.filter((note) => note.relative_path.toLowerCase().includes(needle));
  }, [notes, search]);

  const useSignatureForOutput = useSignature || status.selected_recipients.length === 0;
  const recipientsLabel =
    useSignatureForOutput
      ? "Anyone"
      : status.selected_recipients.length === 0
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
  const filteredOrderedKeys = useMemo(() => {
    const needle = keySearch.trim().toLowerCase();
    if (!needle) {
      return orderedKeys;
    }
    return orderedKeys.filter((key) => {
      const primaryId = key.user_ids.join(" ").toLowerCase();
      return (
        primaryId.includes(needle) ||
        key.fingerprint.toLowerCase().includes(needle) ||
        key.key_id.toLowerCase().includes(needle)
      );
    });
  }, [keySearch, orderedKeys]);

  const selectedRecipientLabels = useMemo(
    () =>
      status.selected_recipients.map((fingerprint) => {
        const key = keys.find((entry) => entry.fingerprint === fingerprint);
        return {
          fingerprint,
          label: key?.user_ids[0] ?? fingerprint,
        };
      }),
    [keys, status.selected_recipients],
  );
  const selectedKeySummary = useMemo(
    () => keys.find((key) => key.fingerprint === selectedKeyFingerprint) ?? null,
    [keys, selectedKeyFingerprint],
  );
  const latestImportedKeys = useMemo(
    () =>
      (latestImportResult?.imported_fingerprints ?? [])
        .map((fingerprint) => keys.find((key) => key.fingerprint === fingerprint))
        .filter((key): key is KeySummary => Boolean(key)),
    [keys, latestImportResult],
  );
  const latestUnchangedKeys = useMemo(
    () =>
      (latestImportResult?.unchanged_fingerprints ?? [])
        .map((fingerprint) => keys.find((key) => key.fingerprint === fingerprint))
        .filter((key): key is KeySummary => Boolean(key)),
    [keys, latestImportResult],
  );
  const selectedX509Certificate = useMemo(
    () =>
      x509Certificates.find((certificate) => certificate.fingerprint === selectedX509Fingerprint) ?? null,
    [selectedX509Fingerprint, x509Certificates],
  );
  const selectedX509RecipientLabels = useMemo(
    () =>
      selectedX509Recipients.map((fingerprint) => {
        const certificate = x509Certificates.find((entry) => entry.fingerprint === fingerprint);
        return {
          fingerprint,
          label: certificate?.subject ?? fingerprint,
        };
      }),
    [selectedX509Recipients, x509Certificates],
  );
  const smartcardMovableKeyOptions = useMemo(() => {
    if (!selectedKeyDetails) {
      return [] as Array<{
        fingerprint: string;
        label: string;
        slot: (typeof smartcardSlotOptions)[number]["value"];
      }>;
    }

    const options: Array<{
      fingerprint: string;
      label: string;
      slot: (typeof smartcardSlotOptions)[number]["value"];
    }> = [];

    if (selectedKeyDetails.summary.has_secret) {
      options.push({
        fingerprint: selectedKeyDetails.summary.fingerprint,
        label: `${selectedKeyDetails.summary.user_ids[0] ?? "Primary key"} (${selectedKeyDetails.summary.capabilities.join("/") || "primary"})`,
        slot: defaultSmartcardSlotForCapabilities(selectedKeyDetails.summary.capabilities),
      });
    }

    for (const subkey of selectedKeyDetails.subkeys) {
      if (!subkey.has_secret) {
        continue;
      }
      options.push({
        fingerprint: subkey.fingerprint,
        label: `${subkey.algorithm} ${subkey.capabilities.join("/") || "subkey"} (${formatFingerprint(subkey.fingerprint)})`,
        slot: defaultSmartcardSlotForCapabilities(subkey.capabilities),
      });
    }

    return options;
  }, [selectedKeyDetails]);

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

  async function persistPinnedSettings(
    nextPrivateKeyFingerprint: string | null,
    nextRecipientFingerprints: string[],
  ) {
    const normalizedRecipients = [...new Set(nextRecipientFingerprints)].sort();
    await savePinnedKeySettings(nextPrivateKeyFingerprint, normalizedRecipients);
    setPinnedPrivateKey(nextPrivateKeyFingerprint);
    setPinnedRecipients(normalizedRecipients);
  }

  function upsertSavedVault(path: string, label: string) {
    const trimmedPath = path.trim();
    const trimmedLabel = label.trim() || deriveVaultLabel(trimmedPath);
    if (!trimmedPath) {
      return;
    }

    setSavedVaults((current) => {
      const next = current.filter((vault) => vault.path !== trimmedPath);
      next.push({ path: trimmedPath, label: trimmedLabel });
      return next.sort((left, right) => left.label.localeCompare(right.label));
    });
  }

  async function openVaultPath(path: string, label = "Opening vault...", recursive = status.recursive_scan) {
    await withBusy(label, async () => {
      const nextNotes = await openFolderVault(path, recursive);
      setNotes(nextNotes);
      setSelectedNote(null);
      setEditorValue("");
      setDirty(false);
      await refreshStatus();
      recordActivity("note", "Opened folder vault", path);
    });
  }

  async function openArchivePath(
    path: string,
    label = "Opening archive vault...",
    recursive = status.recursive_scan,
  ) {
    await withBusy(label, async () => {
      const nextNotes = await openArchiveVault(path, recursive);
      setNotes(nextNotes);
      setSelectedNote(null);
      setEditorValue("");
      setDirty(false);
      await refreshStatus();
      recordActivity("note", "Opened archive vault", path);
    });
  }

  function openSaveVaultDialog(path: string, label?: string) {
    setVaultPathInput(path);
    setVaultLabelInput(label ?? deriveVaultLabel(path));
    setIsVaultSaveDialogOpen(true);
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
      await openVaultPath(selected, "Opening vault...");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleOpenSavedVault(vault: SavedVault) {
    if (vault.path.toLowerCase().endsWith(".zip")) {
      await openArchivePath(vault.path, `Opening ${vault.label}...`);
      return;
    }
    await openVaultPath(vault.path, `Opening ${vault.label}...`);
  }

  function handlePinCurrentVault() {
    if (!status.vault_path) {
      return;
    }
    setPinnedVaultPath((current) => (current === status.vault_path ? null : status.vault_path));
  }

  async function handleBrowseAndSaveVault() {
    try {
      setError(null);
      const selected =
        backendMode === "tauri"
          ? await open({ directory: true, multiple: false, title: "Save Folder Vault" })
          : window.prompt("Mock mode folder label", "Demo Vault");
      if (!selected || Array.isArray(selected)) {
        return;
      }

      openSaveVaultDialog(selected);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  function handleConfirmSaveVault() {
    if (!vaultPathInput.trim()) {
      return;
    }

    upsertSavedVault(vaultPathInput, vaultLabelInput);
    setIsVaultSaveDialogOpen(false);
    setVaultPathInput("");
    setVaultLabelInput("");
  }

  function handleRemoveSavedVault(path: string) {
    setSavedVaults((current) => current.filter((vault) => vault.path !== path));
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
        const summaries: string[] = [];
        for (const path of paths) {
          const result = await importKey(path);
          summaries.push(result.summary);
          setLatestImportResult(result);
          focusImportedKey(result);
          recordActivity("key", "Imported key file", `${filePathLabel(path)}. ${result.summary}`);
        }
        if (summaries.length > 1) {
          setLatestImportResult({
            imported: 0,
            unchanged: 0,
            secret_imported: 0,
            fingerprints: [],
            imported_fingerprints: [],
            unchanged_fingerprints: [],
            summary: summaries.join(" "),
          });
        }
        await refreshKeys();
        await refreshStatus();
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleImportClipboard() {
    try {
      setError(null);
      const clipboardText = await navigator.clipboard.readText();
      if (!clipboardText.trim()) {
        throw new Error("Clipboard is empty.");
      }

      await withBusy("Importing key from clipboard...", async () => {
        const result = await importKeyText(clipboardText);
        setLatestImportResult(result);
        focusImportedKey(result);
        recordActivity("key", "Imported key from clipboard", result.summary);
        await refreshKeys();
        await refreshStatus();
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleOpenArchive() {
    try {
      setError(null);
      const selected =
        backendMode === "tauri"
          ? await open({
              directory: false,
              multiple: false,
              title: "Open Archive Vault",
              filters: [{ name: "ZIP archives", extensions: ["zip"] }],
            })
          : window.prompt("Mock mode archive vault", "demo-vault.zip");
      if (!selected || Array.isArray(selected)) {
        return;
      }

      await openArchivePath(selected, "Opening archive vault...");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  function recordActivity(kind: ActivityKind, title: string, detail: string) {
    const entry: ActivityItem = {
      id: crypto.randomUUID(),
      at: Date.now(),
      kind,
      title,
      detail,
    };
    setActivityLog((current) => [entry, ...current].slice(0, 30));
  }

  function focusImportedKey(result: ImportKeyResult) {
    const first =
      result.imported_fingerprints[0] ??
      result.unchanged_fingerprints[0] ??
      result.fingerprints[0];
    if (first) {
      setSelectedKeyFingerprint(first);
      setActiveTab("keyring");
    }
  }

  async function handleLookupKey() {
    if (!lookupQuery.trim()) {
      return;
    }

    await withBusy("Looking up keys...", async () => {
      const result = await lookupKey(lookupQuery.trim());
      setLatestImportResult(result);
      focusImportedKey(result);
      recordActivity("key", "Looked up public key", result.summary);
      setIsLookupDialogOpen(false);
      setLookupQuery("");
      await refreshKeys();
      await refreshStatus();
    });
  }

  async function handleSearchKeyserver() {
    if (!lookupQuery.trim()) {
      return;
    }

    setIsSearchingKeyserver(true);
    try {
      setKeyserverResults(await searchKeyserver(lookupQuery.trim()));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setIsSearchingKeyserver(false);
    }
  }

  async function handleImportKeyserverResult(fingerprint: string) {
    await withBusy("Importing key from keyserver...", async () => {
      const result = await importKeyFromKeyserver(fingerprint);
      setLatestImportResult(result);
      focusImportedKey(result);
      recordActivity("key", "Imported key from keyserver", result.summary);
      await refreshKeys();
      await refreshStatus();
    });
  }

  async function handleUnlock() {
    await withBusy("Unlocking session...", async () => {
      await unlockSession(passphrase);
      setPassphrase("");
      await refreshStatus();
      recordActivity("session", "Unlocked session", "Private-key operations are available.");
    });
  }

  async function handleSelectNote(note: NoteSummary) {
    await withBusy(`Opening ${note.name}...`, async () => {
      let opened: Awaited<ReturnType<typeof openNote>>;
      try {
        opened = await openNote(note.id);
      } catch (cause) {
        const password = window.prompt("Password for this note");
        if (!password) {
          throw cause;
        }
        opened = await openNoteWithPassword(note.id, password);
      }
      setSelectedNote(opened.note);
      setEditorValue(opened.content);
      setDirty(false);
      setShowRecipients(autoShowRecipients);
      setIsPgpPreviewOpen(autoShowPgpBlock);
      await refreshNoteEncryption(opened.note.id);
      await refreshStatus();
      recordActivity("note", "Opened note", opened.note.relative_path);
    });
  }

  async function handleSave() {
    if (!selectedNote) {
      return;
    }
    await withBusy(`Saving ${selectedNote.name}...`, async () => {
      await saveNote(selectedNote.id, editorValue, useSignatureForOutput);
      setDirty(false);
      await refreshNotes();
      await refreshNoteEncryption(selectedNote.id);
      recordActivity(
        "note",
        useSignatureForOutput ? "Saved signed note" : "Saved encrypted note",
        selectedNote.relative_path,
      );
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

  async function handleCopyPgpPreview() {
    if (!pgpPreview || pgpPreviewError) {
      return;
    }

    try {
      await navigator.clipboard.writeText(pgpPreview);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleUseSignatureToggle(checked: boolean) {
    if (!checked) {
      if (selectedNote && status.session_unlocked && status.selected_recipients.length > 0) {
        await withBusy("Encrypting note to selected recipients...", async () => {
          await saveNote(selectedNote.id, editorValue, false);
          setDirty(false);
          await refreshNotes();
          await refreshNoteEncryption(selectedNote.id);
        });
      }
      setUseSignature(false);
      return;
    }

    const message =
      "Use Signature creates a clear-signed PGP signature. It is not encrypted to specific people, so anyone who can access the saved file or copied PGP block can read the note content. Continue?";
    const approved =
      backendMode === "tauri"
        ? await confirm(message, {
            title: "Use Signature",
            kind: "warning",
            okLabel: "Use Signature",
            cancelLabel: "Cancel",
          })
        : window.confirm(message);

    if (approved) {
      setUseSignature(true);
      if (selectedNote && status.session_unlocked) {
        await withBusy("Saving note as a clear-signed signature...", async () => {
          await saveNote(selectedNote.id, editorValue, true);
          setDirty(false);
          await refreshNotes();
          await refreshNoteEncryption(selectedNote.id);
        });
      }
    }
  }

  async function handleCreateKey() {
    if (createKeyInFlightRef.current) {
      return;
    }

    createKeyInFlightRef.current = true;
    setIsCreatingKey(true);

    try {
      await withBusy("Creating key...", async () => {
        await createKey(newKeyName, newKeyEmail, newKeyPassphrase);
        setIsCreateKeyOpen(false);
        setNewKeyName("");
        setNewKeyEmail("");
        setNewKeyPassphrase("");
        await refreshKeys();
        await refreshStatus();
        recordActivity("key", "Created keypair", `${newKeyName.trim()} <${newKeyEmail.trim()}>`);
      });
    } finally {
      createKeyInFlightRef.current = false;
      setIsCreatingKey(false);
    }
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
      recordActivity("key", "Exported public key", `${keyDisplayName(key)} to ${filePathLabel(outputPath)}`);
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
        recordActivity(
          "key",
          "Exported private key",
          `${keyDisplayName(exportTargetKey)} to ${filePathLabel(outputPath)}`,
        );
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
        recordActivity(
          "key",
          "Exported keypair",
          `${keyDisplayName(exportTargetKey)} to ${filePathLabel(publicPath)} and ${filePathLabel(privatePath)}`,
        );
      });
    }

    setIsExportDialogOpen(false);
    setExportTargetKey(null);
    setExportPassphrase("");
  }

  function openKeyToolsDialog() {
    if (!selectedKeySummary) {
      return;
    }
    setKeyExpiryInput(formatDateInput(selectedKeySummary.expires_at));
    setOwnertrustInput(ownertrustValueFromLabel(selectedKeySummary.trust));
    setSubkeyPreset("encrypt");
    setSubkeyExpireInput("1y");
    setNewKeyPassphraseInput("");
    setConfirmKeyPassphraseInput("");
    setRevocationPassphrase("");
    setIsKeyToolsOpen(true);
  }

  async function handleSaveKeyExpiry() {
    if (!selectedKeySummary || !keyExpiryInput.trim()) {
      return;
    }
    await withBusy("Updating key expiration...", async () => {
      const result = await setKeyExpiry(selectedKeySummary.fingerprint, keyExpiryInput.trim());
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Updated key expiration", result.summary);
    });
  }

  async function handleSaveOwnertrust() {
    if (!selectedKeySummary) {
      return;
    }
    await withBusy("Updating key trust...", async () => {
      const result = await setKeyOwnertrust(selectedKeySummary.fingerprint, ownertrustInput);
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Updated ownertrust", result.summary);
    });
  }

  async function handleCertifySelectedKey(localOnly: boolean) {
    if (!selectedKeySummary) {
      return;
    }
    await withBusy(localOnly ? "Adding local certification..." : "Certifying key...", async () => {
      const result = await certifyKey(selectedKeySummary.fingerprint, localOnly);
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", localOnly ? "Local certification added" : "Certified key", result.summary);
    });
  }

  async function handlePublishSelectedKey() {
    if (!selectedKeySummary) {
      return;
    }
    await withBusy("Publishing key to keyserver...", async () => {
      const result = await publishKeyToKeyserver(selectedKeySummary.fingerprint);
      setLatestKeyAction(result);
      recordActivity("key", "Published key", result.summary);
    });
  }

  async function handleRefreshSelectedKey() {
    if (!selectedKeySummary) {
      return;
    }
    await withBusy("Refreshing key from keyserver...", async () => {
      const result = await refreshKeyFromKeyserver(selectedKeySummary.fingerprint);
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Refreshed key", result.summary);
    });
  }

  async function handleRefreshAllKeys() {
    await withBusy("Refreshing keyring from keyserver...", async () => {
      const result = await refreshAllKeysFromKeyserver();
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Refreshed keyring", result.summary);
    });
  }

  async function handleAddSubkey() {
    if (!selectedKeySummary || !subkeyExpireInput.trim()) {
      return;
    }
    const preset = subkeyPresetOptions.find((option) => option.value === subkeyPreset);
    if (!preset) {
      return;
    }
    await withBusy(`Adding ${preset.label.toLowerCase()} subkey...`, async () => {
      const result = await addSubkey(
        selectedKeySummary.fingerprint,
        preset.algorithm,
        preset.usage,
        subkeyExpireInput.trim(),
      );
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Added subkey", result.summary);
    });
  }

  async function handleChangeKeyPassphrase() {
    if (!selectedKeySummary?.has_secret) {
      return;
    }
    const nextPassphrase = newKeyPassphraseInput;
    if (!nextPassphrase) {
      setError("Enter a new key passphrase.");
      return;
    }
    if (nextPassphrase !== confirmKeyPassphraseInput) {
      setError("New key passphrase confirmation does not match.");
      return;
    }

    await withBusy("Changing key passphrase...", async () => {
      const result = await changeKeyPassphrase(selectedKeySummary.fingerprint, nextPassphrase);
      setLatestKeyAction(result);
      setNewKeyPassphraseInput("");
      setConfirmKeyPassphraseInput("");
      await refreshStatus();
      recordActivity("key", "Changed key passphrase", result.summary);
    });
  }

  async function handleExportRevocationCertificate() {
    if (!selectedKeySummary || !revocationPassphrase) {
      return;
    }
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export Revocation Certificate",
            defaultPath: `${keyFileStem(selectedKeySummary)}-revocation.asc`,
            filters: [{ name: "ASCII-armored certificates", extensions: ["asc"] }],
          })
        : `${keyFileStem(selectedKeySummary)}-revocation.asc`;
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting revocation certificate...", async () => {
      const result = await exportRevocationCertificate(
        selectedKeySummary.fingerprint,
        revocationPassphrase,
        outputPath,
      );
      setLatestKeyAction(result);
      recordActivity(
        "key",
        "Exported revocation certificate",
        `${keyDisplayName(selectedKeySummary)} to ${filePathLabel(outputPath)}`,
      );
    });
  }

  async function handleExportOwnertrust() {
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export Ownertrust",
            defaultPath: "ownertrust.txt",
            filters: [{ name: "Ownertrust snapshot", extensions: ["txt"] }],
          })
        : "ownertrust.txt";
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting ownertrust...", async () => {
      const result = await exportOwnertrust(outputPath);
      setLatestKeyAction(result);
      recordActivity("key", "Exported ownertrust", result.summary);
    });
  }

  async function handleRestartSmartcardService() {
    await withBusy("Restarting smartcard service...", async () => {
      const result = await restartSmartcardService();
      setLatestKeyAction(result);
      const next = await refreshSmartcardStatus();
      recordActivity("key", "Restarted smartcard service", next?.summary ?? result.summary);
    });
  }

  async function handleChangeSmartcardPin() {
    await withBusy("Opening smartcard PIN workflow...", async () => {
      const result = await changeSmartcardPin();
      setLatestKeyAction(result);
      const next = await refreshSmartcardStatus();
      recordActivity("key", "Smartcard PIN workflow", next?.summary ?? result.summary);
    });
  }

  async function handleFetchSmartcardPublicKey() {
    await withBusy("Fetching linked public key from hardware token...", async () => {
      const result = await fetchSmartcardPublicKey();
      setLatestKeyAction(result);
      await refreshKeys();
      const next = await refreshSmartcardStatus();
      recordActivity("key", "Fetched linked public key from hardware token", next?.summary ?? result.summary);
    });
  }

  async function handleCreateSmartcardKeyStubs() {
    await withBusy("Creating local shadow keys from hardware token...", async () => {
      const result = await createSmartcardKeyStubs();
      setLatestKeyAction(result);
      await refreshKeys();
      const next = await refreshSmartcardStatus();
      recordActivity("key", "Created local shadow keys from hardware token", next?.summary ?? result.summary);
    });
  }

  async function handleGenerateSmartcardKey() {
    await withBusy("Generating key material on hardware token...", async () => {
      const result = await generateSmartcardKey(
        smartcardGenerateSlot,
        smartcardGenerateAlgorithm,
        smartcardGenerateForce,
      );
      setLatestKeyAction(result);
      setIsSmartcardGenerateDialogOpen(false);
      setSmartcardGenerateForce(false);
      await refreshSmartcardStatus();
      await refreshKeys();
      recordActivity("key", "Generated on-card key material", result.summary);
    });
  }

  async function handleFactoryResetSmartcard() {
    const approved =
      backendMode === "tauri"
        ? await confirm(
            "Factory reset will erase keys and data on the selected hardware token and restore default PINs. Continue?",
            {
              title: "Factory Reset Hardware Token",
              kind: "warning",
              okLabel: "Reset Token",
              cancelLabel: "Cancel",
            },
          )
        : window.confirm(
            "Factory reset will erase keys and data on the selected hardware token and restore default PINs. Continue?",
          );
    if (!approved) {
      return;
    }

    await withBusy("Running hardware token factory reset...", async () => {
      const result = await factoryResetSmartcard();
      setLatestKeyAction(result);
      await refreshSmartcardStatus();
      await refreshKeys();
      recordActivity("key", "Factory reset hardware token", result.summary);
    });
  }

  function openSmartcardStoreDialog() {
    const firstOption = smartcardMovableKeyOptions[0];
    if (!firstOption) {
      return;
    }
    setSmartcardStoreFingerprint(firstOption.fingerprint);
    setSmartcardStoreSlot(firstOption.slot);
    setSmartcardStoreForce(false);
    setIsSmartcardStoreDialogOpen(true);
  }

  async function handleStoreSecretKeyToSmartcard() {
    await withBusy("Storing local secret key on hardware token...", async () => {
      const result = await moveSecretKeyToSmartcard(
        smartcardStoreFingerprint,
        smartcardStoreSlot,
        smartcardStoreForce,
      );
      setLatestKeyAction(result);
      setIsSmartcardStoreDialogOpen(false);
      setSmartcardStoreForce(false);
      await refreshSmartcardStatus();
      await refreshKeys();
      if (selectedKeySummary) {
        setSelectedKeyDetails(await getKeyDetails(selectedKeySummary.fingerprint));
      }
      recordActivity("key", "Stored secret key on hardware token", result.summary);
    });
  }

  async function handleImportOwnertrust() {
    const inputPath =
      backendMode === "tauri"
        ? await open({
            directory: false,
            multiple: false,
            title: "Import Ownertrust",
            filters: [{ name: "Ownertrust snapshot", extensions: ["txt"] }],
          })
        : window.prompt("Mock mode ownertrust file", "ownertrust.txt");
    if (!inputPath || Array.isArray(inputPath)) {
      return;
    }

    await withBusy("Importing ownertrust...", async () => {
      const result = await importOwnertrust(inputPath);
      setLatestKeyAction(result);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Imported ownertrust", result.summary);
    });
  }

  async function handleImportX509Certificate() {
    const path =
      backendMode === "tauri"
        ? await open({
            directory: false,
            multiple: false,
            title: "Import X.509 Certificate",
            filters: [{ name: "Certificates", extensions: ["cer", "crt", "pem", "p7b", "p12", "pfx"] }],
          })
        : window.prompt("Mock mode X.509 certificate", "demo-cert.pem");
    if (!path || Array.isArray(path)) {
      return;
    }

    await withBusy("Importing X.509 certificate...", async () => {
      const result = await importX509Certificate(path);
      setLatestKeyAction(result);
      await refreshX509Certificates();
      recordActivity("key", "Imported X.509 certificate", result.summary);
    });
  }

  async function handleImportX509CertificateText() {
    await withBusy("Importing pasted X.509 certificate...", async () => {
      const result = await importX509CertificateText(pastedX509CertificateText);
      setLatestKeyAction(result);
      await refreshX509Certificates();
      setIsPasteX509DialogOpen(false);
      setPastedX509CertificateText("");
      recordActivity("key", "Imported X.509 certificate from text", result.summary);
    });
  }

  async function handleLearnX509Card() {
    await withBusy("Learning X.509 certificates from smartcard...", async () => {
      const result = await learnX509Card();
      setLatestKeyAction(result);
      await refreshX509Certificates();
      const next = await refreshSmartcardStatus();
      recordActivity("key", "Learned X.509 certificates from smartcard", next?.summary ?? result.summary);
    });
  }

  async function handleCreateX509Certificate() {
    setIsCreatingX509Certificate(true);
    try {
      await withBusy("Creating X.509 certificate...", async () => {
        const result = await createX509Certificate(
          newX509CommonName,
          newX509Organization,
          newX509Email,
          newX509Expiry,
          newX509Passphrase,
        );
        setLatestKeyAction(result);
        await refreshX509Certificates();
        setSelectedX509Fingerprint(result.fingerprint === "x509" ? null : result.fingerprint);
        setIsCreateX509DialogOpen(false);
        setNewX509CommonName("");
        setNewX509Organization("");
        setNewX509Email("");
        setNewX509Expiry(defaultX509ExpiryDate());
        setNewX509Passphrase("");
        recordActivity("key", "Created X.509 certificate", result.summary);
      });
    } finally {
      setIsCreatingX509Certificate(false);
    }
  }

  async function handleExportX509Certificate(certificate: X509CertificateSummary) {
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export X.509 Certificate",
            defaultPath: `${certificate.subject.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "certificate"}.pem`,
            filters: [{ name: "PEM certificate", extensions: ["pem", "cer", "crt"] }],
          })
        : "certificate.pem";
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting X.509 certificate...", async () => {
      const result = await exportX509Certificate(certificate.fingerprint, outputPath);
      setLatestKeyAction(result);
      recordActivity("key", "Exported X.509 certificate", result.summary);
    });
  }

  async function handleExportX509SecretKey(certificate: X509CertificateSummary) {
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export PKCS#12 Bundle",
            defaultPath: `${certificate.subject.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "certificate"}.p12`,
            filters: [{ name: "PKCS#12 bundle", extensions: ["p12", "pfx"] }],
          })
        : "certificate.p12";
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting PKCS#12 bundle...", async () => {
      const result = await exportX509SecretKeyP12(certificate.fingerprint, outputPath);
      setLatestKeyAction(result);
      recordActivity("key", "Exported PKCS#12 bundle", result.summary);
    });
  }

  async function handleExportX509SecretKeyP8(certificate: X509CertificateSummary) {
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export PKCS#8 Key",
            defaultPath: `${certificate.subject.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").toLowerCase() || "certificate"}-key.pem`,
            filters: [{ name: "PKCS#8 key", extensions: ["pem", "key", "p8"] }],
          })
        : "certificate-key.pem";
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting PKCS#8 key...", async () => {
      const result = await exportX509SecretKeyP8(certificate.fingerprint, outputPath);
      setLatestKeyAction(result);
      recordActivity("key", "Exported PKCS#8 key", result.summary);
    });
  }

  async function handleChangeX509Passphrase(certificate: X509CertificateSummary) {
    await withBusy("Opening X.509 passphrase workflow...", async () => {
      const result = await changeX509Passphrase(certificate.fingerprint);
      setLatestKeyAction(result);
      recordActivity("key", "X.509 passphrase workflow", result.summary);
    });
  }

  async function handleDeleteX509Certificate(certificate: X509CertificateSummary) {
    const approved =
      backendMode === "tauri"
        ? await confirm(`Remove ${certificate.subject} from the X.509 certificate store?`, {
            title: "Remove X.509 certificate",
            kind: "warning",
            okLabel: "Remove",
            cancelLabel: "Cancel",
          })
        : window.confirm(`Remove ${certificate.subject} from the X.509 certificate store?`);
    if (!approved) {
      return;
    }

    await withBusy("Removing X.509 certificate...", async () => {
      const result = await deleteX509Certificate(certificate.fingerprint);
      setLatestKeyAction(result);
      await refreshX509Certificates();
      setSelectedX509Recipients((current) =>
        current.filter((fingerprint) => fingerprint !== certificate.fingerprint),
      );
      if (selectedX509SignerFingerprint === certificate.fingerprint) {
        setSelectedX509SignerFingerprint(null);
      }
      recordActivity("key", "Removed X.509 certificate", result.summary);
    });
  }

  function handleX509SignerSelection(fingerprint: string) {
    setSelectedX509SignerFingerprint(fingerprint);
    recordActivity("key", "Selected X.509 signing certificate", formatFingerprint(fingerprint));
  }

  function handleX509RecipientSelection(fingerprint: string, checked: boolean) {
    setSelectedX509Recipients((current) =>
      checked ? [...new Set([...current, fingerprint])] : current.filter((value) => value !== fingerprint),
    );
  }

  async function handleRefreshX509Validation(certificate: X509CertificateSummary) {
    await withBusy("Refreshing X.509 validation...", async () => {
      const chain = await getX509CertificateChain(certificate.fingerprint);
      setSelectedX509Chain(chain);
      recordActivity("key", "Refreshed X.509 validation", certificate.subject);
    });
  }

  async function handleImportX509Crl() {
    const path =
      backendMode === "tauri"
        ? await open({
            directory: false,
            multiple: false,
            title: "Import Certificate Revocation List",
            filters: [{ name: "Certificate revocation lists", extensions: ["crl", "pem", "der"] }],
          })
        : window.prompt("Mock mode CRL file", "demo.crl");
    if (!path || Array.isArray(path)) {
      return;
    }

    await withBusy("Loading certificate revocation data...", async () => {
      const result = await importX509Crl(path);
      setLatestKeyAction(result);
      if (selectedX509Certificate) {
        const chain = await getX509CertificateChain(selectedX509Certificate.fingerprint);
        setSelectedX509Chain(chain);
      }
      recordActivity("key", "Loaded certificate revocation data", result.summary);
    });
  }

  async function handleSetX509TrustRoot(certificate: X509CertificateSummary, trusted: boolean) {
    await withBusy(trusted ? "Marking certificate as trusted root..." : "Removing trusted root mark...", async () => {
      const result = await setX509TrustRoot(certificate.fingerprint, trusted);
      setLatestKeyAction(result);
      await refreshX509Certificates();
      const chain = await getX509CertificateChain(certificate.fingerprint);
      setSelectedX509Chain(chain);
      recordActivity(
        "key",
        trusted ? "Marked trusted root certificate" : "Removed trusted root certificate",
        certificate.subject,
      );
    });
  }

  async function handleExportX509Trustlist() {
    const outputPath =
      backendMode === "tauri"
        ? await saveDialog({
            title: "Export Trusted Root Certificates",
            defaultPath: "trustlist.txt",
            filters: [{ name: "Trust list", extensions: ["txt"] }],
          })
        : "trustlist.txt";
    if (!outputPath || Array.isArray(outputPath)) {
      return;
    }

    await withBusy("Exporting trusted root certificates...", async () => {
      const result = await exportX509Trustlist(outputPath);
      setLatestKeyAction(result);
      recordActivity("key", "Exported trusted root certificates", result.summary);
    });
  }

  async function handleImportX509Trustlist() {
    const inputPath =
      backendMode === "tauri"
        ? await open({
            directory: false,
            multiple: false,
            title: "Import Trusted Root Certificates",
            filters: [{ name: "Trust list", extensions: ["txt"] }],
          })
        : window.prompt("Mock mode trust list", "trustlist.txt");
    if (!inputPath || Array.isArray(inputPath)) {
      return;
    }

    await withBusy("Importing trusted root certificates...", async () => {
      const result = await importX509Trustlist(inputPath);
      setLatestKeyAction(result);
      await refreshX509Certificates();
      if (selectedX509Certificate) {
        const chain = await getX509CertificateChain(selectedX509Certificate.fingerprint);
        setSelectedX509Chain(chain);
      }
      recordActivity("key", "Imported trusted root certificates", result.summary);
    });
  }

  async function handleCreate() {
    const name = window.prompt("New note name");
    if (!name) {
      return;
    }
    const normalized = normalizeNoteName(name);
    await withBusy(`Creating ${normalized}...`, async () => {
      const created = await createNote(normalized, "", useSignatureForOutput);
      await refreshNotes();
      await handleSelectNote(created);
      recordActivity("note", "Created note", normalized);
    });
  }

  async function handleSaveWithPassword() {
    if (!selectedNote) {
      return;
    }
    const password = window.prompt("Password for this note");
    if (!password) {
      return;
    }
    await withBusy(`Saving ${selectedNote.name} with password...`, async () => {
      await saveNoteWithPassword(selectedNote.id, editorValue, password);
      setDirty(false);
      await refreshNotes();
      await refreshNoteEncryption(selectedNote.id);
      recordActivity("note", "Saved password-protected note", selectedNote.relative_path);
    });
  }

  async function createNoteFromPreparedClipboard(
    content: string,
    busyLabel: string,
    clipboardSignature: NoteSignatureStatus | null = null,
  ) {
    const name = window.prompt("New note name");
    if (!name) {
      return;
    }

    const normalized = normalizeNoteName(name);
    await withBusy(busyLabel.replace("{name}", normalized), async () => {
      const created = await createNote(normalized, content, useSignatureForOutput);
      await refreshNotes();
      await handleSelectNote(created);
      if (clipboardSignature) {
        setNoteEncryptionStatus((current) => ({
          ...current,
          signature: clipboardSignature,
        }));
      }
      recordActivity("note", "Created note from clipboard", normalized);
    });
  }

  async function handleCreateFromClipboard() {
    try {
      setError(null);
      const clipboardText = await navigator.clipboard.readText();
      if (!clipboardText.trim()) {
        throw new Error("Clipboard is empty.");
      }

      const trimmed = clipboardText.trim();
      if (isPgpSignatureBlock(trimmed) && !isPgpSignedMessageBlock(trimmed)) {
        if (!selectedNote) {
          throw new Error("Open a note before verifying a detached PGP signature.");
        }
        const signature = await verifyClipboardSignature(trimmed, editorValue);
        setNoteEncryptionStatus((current) => ({
          ...current,
          signature,
        }));
        setShowRecipients(true);
        return;
      }

      const prepared = await resolveClipboardNoteContent(clipboardText);
      await createNoteFromPreparedClipboard(
        prepared.content,
        prepared.was_decrypted
          ? "Creating {name} from decrypted clipboard message..."
          : "Creating {name} from clipboard...",
        prepared.signature,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  async function handleClipboardPasteAction(clipboardText: string) {
    const trimmed = clipboardText.trim();
    if (!trimmed || busy) {
      return false;
    }

    if (isPgpKeyBlock(trimmed)) {
      const approved =
        backendMode === "tauri"
          ? await confirm("Import the OpenPGP key currently in your clipboard?", {
              title: "Import clipboard key",
              kind: "info",
            })
          : window.confirm("Import the OpenPGP key currently in your clipboard?");
      if (!approved) {
        return true;
      }

      await withBusy("Importing key from clipboard...", async () => {
        const result = await importKeyText(trimmed);
        setLatestImportResult(result);
        focusImportedKey(result);
        recordActivity("key", "Imported key from clipboard", result.summary);
        await refreshKeys();
        await refreshStatus();
      });
      return true;
    }

    if (isPgpSignedMessageBlock(trimmed)) {
      const prepared = await resolveClipboardNoteContent(trimmed);
      if (!prepared.was_decrypted) {
        return false;
      }

      await createNoteFromPreparedClipboard(
        prepared.content,
        "Creating {name} from signed clipboard message...",
        prepared.signature,
      );
      return true;
    }

    if (isPgpSignatureBlock(trimmed) && !isPgpSignedMessageBlock(trimmed)) {
      if (!selectedNote) {
        setError("Open a note before pasting a detached PGP signature.");
        return true;
      }

      const signature = await verifyClipboardSignature(trimmed, editorValue);
      setNoteEncryptionStatus((current) => ({
        ...current,
        signature,
      }));
      setShowRecipients(true);
      setError(null);
      return true;
    }

    if (!isPgpMessageBlock(trimmed) || !status.session_unlocked || !status.selected_private_key) {
      return false;
    }

    const prepared = await resolveClipboardNoteContent(trimmed);
    if (!prepared.was_decrypted) {
      return false;
    }

    await createNoteFromPreparedClipboard(
      prepared.content,
      "Creating {name} from decrypted clipboard message...",
      prepared.signature,
    );
    return true;
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
      recordActivity("note", "Renamed note", `${selectedNote.relative_path} -> ${normalized}`);
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
      recordActivity("note", "Deleted note", selectedNote.relative_path);
    });
  }

  async function handlePrivateKeySelection(fingerprint: string) {
    if (pinnedPrivateKey && pinnedPrivateKey !== fingerprint) {
      await persistPinnedSettings(null, pinnedRecipients);
    }

    await withBusy("Selecting private key...", async () => {
      await selectPrivateKey(fingerprint);
      await refreshKeys();
      await refreshStatus();
      recordActivity("key", "Selected private key", formatFingerprint(fingerprint));
    });
  }

  async function handleRecipientSelection(fingerprint: string, checked: boolean) {
    if (!checked && pinnedRecipients.includes(fingerprint)) {
      await persistPinnedSettings(
        pinnedPrivateKey,
        pinnedRecipients.filter((value) => value !== fingerprint),
      );
    }

    const next = checked
      ? [...status.selected_recipients, fingerprint]
      : status.selected_recipients.filter((value) => value !== fingerprint);
    const nextUsesSignature = useSignature || next.length === 0;
    await withBusy(
      selectedNote && status.session_unlocked
        ? "Updating recipients and re-encrypting note..."
        : "Updating recipients...",
      async () => {
      setError(null);
      await setRecipients(next);

      if (selectedNote && status.session_unlocked) {
        await saveNote(selectedNote.id, editorValue, nextUsesSignature);
        setDirty(false);
        await refreshNotes();
      }

      await refreshKeys();
      await refreshStatus();
      if (selectedNote) {
        await refreshNoteEncryption(selectedNote.id);
      }

      },
    );
  }

  async function handleTogglePrivatePin(key: KeySummary) {
    if (!key.has_secret) {
      return;
    }

    if (pinnedPrivateKey === key.fingerprint) {
      await persistPinnedSettings(null, pinnedRecipients);
      return;
    }

    if (!key.is_selected_private) {
      await handlePrivateKeySelection(key.fingerprint);
    }

    await persistPinnedSettings(key.fingerprint, pinnedRecipients);
  }

  async function handleToggleRecipientPin(key: KeySummary) {
    if (pinnedRecipients.includes(key.fingerprint)) {
      await persistPinnedSettings(
        pinnedPrivateKey,
        pinnedRecipients.filter((value) => value !== key.fingerprint),
      );
      return;
    }

    if (!key.is_selected_recipient) {
      await handleRecipientSelection(key.fingerprint, true);
    }

    await persistPinnedSettings(pinnedPrivateKey, [...pinnedRecipients, key.fingerprint]);
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
      await persistPinnedSettings(
        pinnedPrivateKey === key.fingerprint ? null : pinnedPrivateKey,
        pinnedRecipients.filter((fingerprint) => fingerprint !== key.fingerprint),
      );
      await refreshKeys();
      await refreshStatus();
      if (selectedNote) {
        await refreshNoteEncryption(selectedNote.id);
      }
      recordActivity("key", "Removed key", keyDisplayName(key));
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

  async function pickFiles() {
    if (backendMode !== "tauri") {
      const mocked = window.prompt("Mock mode file paths (comma separated)", "report.txt,plan.pdf");
      if (!mocked) {
        return;
      }
      const parsed = mocked
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      if (parsed.length > 0) {
        setSelectedFilePaths((current) => [...new Set([...current, ...parsed])]);
      }
      return;
    }

    const selected = await open({
      directory: false,
      multiple: true,
      title: "Choose Files",
    });
    if (!selected) {
      return;
    }
    const paths = Array.isArray(selected) ? selected : [selected];
    setSelectedFilePaths((current) => [...new Set([...current, ...paths])]);
  }

  async function pickFolders() {
    if (backendMode !== "tauri") {
      const mocked = window.prompt("Mock mode folder paths (comma separated)", "project-docs,photos");
      if (!mocked) {
        return;
      }
      const parsed = mocked
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      if (parsed.length > 0) {
        setSelectedFilePaths((current) => [...new Set([...current, ...parsed])]);
      }
      return;
    }

    const selected = await open({
      directory: true,
      multiple: true,
      title: "Choose Folder",
    });
    if (!selected) {
      return;
    }
    const paths = Array.isArray(selected) ? selected : [selected];
    setSelectedFilePaths((current) => [...new Set([...current, ...paths])]);
  }

  async function pickOutputDirectory() {
    const selected =
      backendMode === "tauri"
        ? await open({ directory: true, multiple: false, title: "Choose Output Folder" })
        : window.prompt("Mock mode output folder", "exports");
    if (!selected || Array.isArray(selected)) {
      return;
    }
    setFileOutputDir(selected);
  }

  async function pickVerifyInputFile() {
    const selected =
      backendMode === "tauri"
        ? await open({ directory: false, multiple: false, title: "Choose File to Verify" })
        : window.prompt("Mock mode file", "report.txt");
    if (!selected || Array.isArray(selected)) {
      return;
    }
    setVerifyInputPath(selected);
  }

  async function pickVerifySignatureFile() {
    const selected =
      backendMode === "tauri"
        ? await open({ directory: false, multiple: false, title: "Choose Signature File" })
        : window.prompt("Mock mode signature", "report.txt.sig");
    if (!selected || Array.isArray(selected)) {
      return;
    }
    setVerifySignaturePath(selected);
  }

  function clearSelectedFiles() {
    if (selectedFilePaths.length > 0 || fileOperationResults.length > 0) {
      recordActivity("file", "Cleared file workspace", "Removed queued files and recent outputs.");
    }
    setSelectedFilePaths([]);
    setFileOperationResults([]);
    setFileVerificationStatus(null);
  }

  function collectDroppedPaths(event: ReactDragEvent<HTMLDivElement>) {
    const droppedPaths = Array.from(event.dataTransfer.files)
      .map((file) => {
        const withPath = file as File & { path?: string };
        return withPath.path ?? "";
      })
      .filter(Boolean);
    return droppedPaths;
  }

  async function handleFileDrop(event: ReactDragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsFileDropActive(false);
    const droppedPaths = collectDroppedPaths(event);
    if (droppedPaths.length === 0) {
      if (backendMode !== "tauri") {
        setError("Drag and drop file paths are only available in the desktop app.");
      }
      return;
    }
    setSelectedFilePaths((current) => [...new Set([...current, ...droppedPaths])]);
  }

  async function runFileOperation(
    label: string,
    activityTitle: string,
    work: () => Promise<FileOperationResult[]>,
  ) {
    await withBusy(label, async () => {
      const results = await work();
      setFileOperationResults(results);
      if (results.length > 0) {
        setFileOutputDir(results[0].output_path.replace(/[\\/][^\\/]+$/, ""));
        recordActivity(
          "file",
          activityTitle,
          `${results.length} file${results.length === 1 ? "" : "s"} -> ${filePathLabel(results[0].output_path)}${results.length > 1 ? " and more" : ""}`,
        );
      }
    });
  }

  async function handleEncryptFiles() {
    if (selectedFilePaths.length === 0 || !fileOutputDir) {
      setError("Choose files and an output folder first.");
      return;
    }
    if (fileCryptoMode === "smime") {
      if (selectedX509Recipients.length === 0) {
        setError("Choose one or more X.509 recipient certificates first.");
        return;
      }
      await runFileOperation("Encrypting CMS files...", "Encrypted CMS files", () =>
        encryptCmsFiles(selectedFilePaths, fileOutputDir, selectedX509Recipients),
      );
      return;
    }
    await runFileOperation("Encrypting files...", "Encrypted files", () =>
      encryptFiles(selectedFilePaths, fileOutputDir),
    );
  }

  async function handleDecryptFiles() {
    if (selectedFilePaths.length === 0 || !fileOutputDir) {
      setError("Choose files and an output folder first.");
      return;
    }
    if (fileCryptoMode === "smime") {
      await runFileOperation("Decrypting CMS files...", "Decrypted CMS files", () =>
        decryptCmsFiles(selectedFilePaths, fileOutputDir),
      );
      return;
    }
    await runFileOperation("Decrypting files...", "Decrypted files", () =>
      decryptFiles(selectedFilePaths, fileOutputDir),
    );
  }

  async function handleSignFiles() {
    if (selectedFilePaths.length === 0 || !fileOutputDir) {
      setError("Choose files and an output folder first.");
      return;
    }
    if (fileCryptoMode === "smime") {
      if (!selectedX509SignerFingerprint) {
        setError("Choose an X.509 signing certificate first.");
        return;
      }
      await runFileOperation("Signing CMS files...", "Signed CMS files", () =>
        signCmsFiles(selectedFilePaths, fileOutputDir, selectedX509SignerFingerprint),
      );
      return;
    }
    await runFileOperation("Signing files...", "Signed files", () =>
      signFiles(selectedFilePaths, fileOutputDir),
    );
  }

  async function handleVerifyFileSignature() {
    if (!verifyInputPath || !verifySignaturePath) {
      setError("Choose a file and signature first.");
      return;
    }
    await withBusy("Verifying signature...", async () => {
      const next =
        fileCryptoMode === "smime"
          ? await verifyCmsFileSignature(verifyInputPath, verifySignaturePath)
          : await verifyFileSignature(verifyInputPath, verifySignaturePath);
      setFileVerificationStatus(next);
      recordActivity("file", "Verified detached signature", next.summary);
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
                  disabled={
                    isCreatingKey || !newKeyName.trim() || !newKeyEmail.trim() || !newKeyPassphrase
                  }
                >
                  {isCreatingKey ? "Creating..." : "Create Key"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isCreateX509DialogOpen} onOpenChange={setIsCreateX509DialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create X.509 Certificate</DialogTitle>
                <DialogDescription>
                  Create a self-signed certificate for CMS and S/MIME workflows.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3">
                <Input
                  value={newX509CommonName}
                  onChange={(event) => setNewX509CommonName(event.target.value)}
                  placeholder="Common name"
                />
                <Input
                  value={newX509Organization}
                  onChange={(event) => setNewX509Organization(event.target.value)}
                  placeholder="Organization (optional)"
                />
                <Input
                  value={newX509Email}
                  onChange={(event) => setNewX509Email(event.target.value)}
                  placeholder="Email (optional)"
                  type="email"
                />
                <Input
                  value={newX509Expiry}
                  onChange={(event) => setNewX509Expiry(event.target.value)}
                  placeholder="YYYY-MM-DD"
                />
                <Input
                  value={newX509Passphrase}
                  onChange={(event) => setNewX509Passphrase(event.target.value)}
                  placeholder="Certificate passphrase"
                  type="password"
                />
              </div>
              <DialogFooter className="gap-2">
                <Button variant="ghost" onClick={() => setIsCreateX509DialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => void handleCreateX509Certificate()}
                  disabled={
                    isCreatingX509Certificate ||
                    !newX509CommonName.trim() ||
                    !newX509Expiry.trim() ||
                    !newX509Passphrase
                  }
                >
                  {isCreatingX509Certificate ? "Creating..." : "Create Certificate"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isPasteX509DialogOpen} onOpenChange={setIsPasteX509DialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Paste X.509 Certificate</DialogTitle>
                <DialogDescription>
                  Import a certificate directly from pasted PEM or other certificate text.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3">
                <Textarea
                  value={pastedX509CertificateText}
                  onChange={(event) => setPastedX509CertificateText(event.target.value)}
                  placeholder="Paste certificate text here"
                  rows={10}
                />
              </div>
              <DialogFooter className="gap-2">
                <Button variant="ghost" onClick={() => setIsPasteX509DialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => void handleImportX509CertificateText()}
                  disabled={!pastedX509CertificateText.trim()}
                >
                  Import Certificate
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isSmartcardGenerateDialogOpen} onOpenChange={setIsSmartcardGenerateDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Generate On-Card Key</DialogTitle>
                <DialogDescription>
                  Create fresh key material directly on the hardware token for one OpenPGP slot.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3">
                <label className="grid gap-1 text-sm text-muted-foreground">
                  <span>Slot</span>
                  <select
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                    value={smartcardGenerateSlot}
                    onChange={(event) =>
                      setSmartcardGenerateSlot(
                        event.target.value as (typeof smartcardSlotOptions)[number]["value"],
                      )
                    }
                  >
                    {smartcardSlotOptions.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-sm text-muted-foreground">
                  <span>Algorithm</span>
                  <select
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                    value={smartcardGenerateAlgorithm}
                    onChange={(event) =>
                      setSmartcardGenerateAlgorithm(
                        event.target.value as (typeof smartcardAlgorithmOptions)[number]["value"],
                      )
                    }
                  >
                    {smartcardAlgorithmOptions.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-background/60 px-3 py-2">
                  <div className="min-w-0">
                    <div className="text-sm text-foreground">Replace existing slot</div>
                    <div className="text-xs text-muted-foreground">
                      Enable only when you intentionally want to overwrite the current card key in this slot.
                    </div>
                  </div>
                  <Switch
                    checked={smartcardGenerateForce}
                    onCheckedChange={setSmartcardGenerateForce}
                  />
                </div>
                <div className="rounded-md border border-border/70 bg-background/60 px-3 py-2 text-xs text-muted-foreground">
                  {smartcardGenerateForce
                    ? "Force mode will overwrite key material already stored in the selected token slot."
                    : "This writes new key material to the selected token slot. Use an empty slot unless you intend to replace existing card keys."}
                </div>
              </div>
              <DialogFooter className="gap-2">
                <Button variant="ghost" onClick={() => setIsSmartcardGenerateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={() => void handleGenerateSmartcardKey()}>
                  Generate Key
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isSmartcardStoreDialogOpen} onOpenChange={setIsSmartcardStoreDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Store Secret Key On Token</DialogTitle>
                <DialogDescription>
                  Move existing local OpenPGP secret key material into a selected hardware token slot.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-3">
                <label className="grid gap-1 text-sm text-muted-foreground">
                  <span>Local key material</span>
                  <select
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                    value={smartcardStoreFingerprint}
                    onChange={(event) => {
                      const fingerprint = event.target.value;
                      setSmartcardStoreFingerprint(fingerprint);
                      const option = smartcardMovableKeyOptions.find((item) => item.fingerprint === fingerprint);
                      if (option) {
                        setSmartcardStoreSlot(option.slot);
                      }
                    }}
                  >
                    {smartcardMovableKeyOptions.map((option) => (
                      <option key={option.fingerprint} value={option.fingerprint}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-sm text-muted-foreground">
                  <span>Token slot</span>
                  <select
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground"
                    value={smartcardStoreSlot}
                    onChange={(event) =>
                      setSmartcardStoreSlot(
                        event.target.value as (typeof smartcardSlotOptions)[number]["value"],
                      )
                    }
                  >
                    {smartcardSlotOptions.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="flex items-center justify-between gap-3 rounded-md border border-border/70 bg-background/60 px-3 py-2">
                  <div className="min-w-0">
                    <div className="text-sm text-foreground">Replace existing slot</div>
                    <div className="text-xs text-muted-foreground">
                      Enable only when you intentionally want to overwrite a token slot that already contains key material.
                    </div>
                  </div>
                  <Switch
                    checked={smartcardStoreForce}
                    onCheckedChange={setSmartcardStoreForce}
                  />
                </div>
                <div className="rounded-md border border-border/70 bg-background/60 px-3 py-2 text-xs text-muted-foreground">
                  {smartcardStoreForce
                    ? "Force mode will overwrite the selected token slot with this local secret key."
                    : "This stores the selected local secret key on the token. Use an empty slot unless you intend to replace existing token keys."}
                </div>
              </div>
              <DialogFooter className="gap-2">
                <Button variant="ghost" onClick={() => setIsSmartcardStoreDialogOpen(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => void handleStoreSecretKeyToSmartcard()}
                  disabled={!smartcardStoreFingerprint}
                >
                  Store Key
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isVaultSaveDialogOpen} onOpenChange={setIsVaultSaveDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Save Vault</DialogTitle>
                <DialogDescription>
                  Save a vault path so it can be reopened quickly from the header.
                </DialogDescription>
              </DialogHeader>
              <div className="flex flex-col gap-3">
                <Input value={vaultLabelInput} onChange={(event) => setVaultLabelInput(event.target.value)} placeholder="Vault name" />
                <Input value={vaultPathInput} onChange={(event) => setVaultPathInput(event.target.value)} placeholder="Vault path" />
              </div>
              <DialogFooter className="gap-2">
                <Button
                  variant="ghost"
                  onClick={() => {
                    setIsVaultSaveDialogOpen(false);
                    setVaultPathInput("");
                    setVaultLabelInput("");
                  }}
                >
                  Cancel
                </Button>
                <Button onClick={handleConfirmSaveVault} disabled={!vaultPathInput.trim()}>
                  Save Vault
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

          <Dialog open={isKeyToolsOpen} onOpenChange={setIsKeyToolsOpen}>
            <DialogContent className="max-h-[min(90vh,56rem)] overflow-hidden p-0 sm:max-w-2xl">
              <div className="flex max-h-[min(90vh,56rem)] flex-col">
              <div className="px-6 pt-6">
              <DialogHeader>
                <DialogTitle>Keyring Tools</DialogTitle>
                <DialogDescription>
                  Update trust and expiry, add a subkey, manage trust snapshots, certify the selected key, or export a revocation certificate.
                </DialogDescription>
              </DialogHeader>
              </div>
              <div className="flex-1 overflow-y-auto px-6 py-4">
              <div className="space-y-4">
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Expiration</label>
                  <div className="flex gap-2">
                    <Input
                      value={keyExpiryInput}
                      onChange={(event) => setKeyExpiryInput(event.target.value)}
                      placeholder="never, 1y, 2027-12-31"
                    />
                    <Button onClick={() => void handleSaveKeyExpiry()} disabled={!selectedKeySummary || !keyExpiryInput.trim()}>
                      Save
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Ownertrust</label>
                  <div className="flex gap-2">
                    <select
                      value={ownertrustInput}
                      onChange={(event) => setOwnertrustInput(event.target.value)}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    >
                      {ownertrustOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <Button onClick={() => void handleSaveOwnertrust()} disabled={!selectedKeySummary}>
                      Save
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Trust Snapshot</label>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="secondary" onClick={() => void handleImportOwnertrust()}>
                      Import
                    </Button>
                    <Button onClick={() => void handleExportOwnertrust()}>
                      Export
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Add Subkey</label>
                  <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_140px_auto]">
                    <select
                      value={subkeyPreset}
                      onChange={(event) =>
                        setSubkeyPreset(event.target.value as (typeof subkeyPresetOptions)[number]["value"])
                      }
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    >
                      {subkeyPresetOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <Input
                      value={subkeyExpireInput}
                      onChange={(event) => setSubkeyExpireInput(event.target.value)}
                      placeholder="1y or never"
                    />
                    <Button onClick={() => void handleAddSubkey()} disabled={!selectedKeySummary || !subkeyExpireInput.trim()}>
                      Add
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Change Passphrase</label>
                  <div className="grid gap-2">
                    <Input
                      value={newKeyPassphraseInput}
                      onChange={(event) => setNewKeyPassphraseInput(event.target.value)}
                      placeholder="New key passphrase"
                      type="password"
                    />
                    <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
                      <Input
                        value={confirmKeyPassphraseInput}
                        onChange={(event) => setConfirmKeyPassphraseInput(event.target.value)}
                        placeholder="Confirm new passphrase"
                        type="password"
                      />
                      <div className="hidden sm:block text-xs text-muted-foreground self-center">
                        Selected private key only
                      </div>
                      <Button
                        onClick={() => void handleChangeKeyPassphrase()}
                        disabled={
                          !selectedKeySummary?.has_secret ||
                          !selectedKeySummary.is_selected_private ||
                          !status.session_unlocked ||
                          !newKeyPassphraseInput ||
                          !confirmKeyPassphraseInput
                        }
                      >
                        Update
                      </Button>
                    </div>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Certification</label>
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => void handleCertifySelectedKey(false)} disabled={!selectedKeySummary}>
                      Certify
                    </Button>
                    <Button variant="secondary" onClick={() => void handleCertifySelectedKey(true)} disabled={!selectedKeySummary}>
                      Local Certify
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Distribution</label>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="secondary" onClick={() => void handleRefreshSelectedKey()} disabled={!selectedKeySummary}>
                      Refresh
                    </Button>
                    <Button onClick={() => void handlePublishSelectedKey()} disabled={!selectedKeySummary}>
                      Publish
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <label className="text-sm font-medium">Revocation Certificate</label>
                  <Input
                    value={revocationPassphrase}
                    onChange={(event) => setRevocationPassphrase(event.target.value)}
                    placeholder="Key passphrase"
                    type="password"
                  />
                  <Button
                    variant="secondary"
                    onClick={() => void handleExportRevocationCertificate()}
                    disabled={!selectedKeySummary || !revocationPassphrase}
                  >
                    Export Revocation
                  </Button>
                </div>
              </div>
              </div>
              <DialogFooter className="border-t px-6 py-4">
                <Button variant="ghost" onClick={() => setIsKeyToolsOpen(false)}>
                  Close
                </Button>
              </DialogFooter>
              </div>
            </DialogContent>
          </Dialog>

          <Dialog open={isLookupDialogOpen} onOpenChange={setIsLookupDialogOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Lookup Public Key</DialogTitle>
                <DialogDescription>
                  Search using email, key ID, or fingerprint. The app uses GnuPG auto-discovery with WKD and a public keyserver.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <Input
                  value={lookupQuery}
                  onChange={(event) => {
                    setLookupQuery(event.target.value);
                    setKeyserverResults([]);
                  }}
                  placeholder="alice@example.com or fingerprint"
                />
                <div className="rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-xs text-muted-foreground">
                  `Lookup` uses WKD and auto-discovery. `Search` browses the public keyserver and lets you import a specific result.
                </div>
                {keyserverResults.length > 0 ? (
                  <div className="max-h-56 space-y-2 overflow-auto rounded-lg border border-border/70 bg-background/30 p-2">
                    {keyserverResults.map((result) => (
                      <div
                        key={result.fingerprint}
                        className="rounded-lg border border-border/70 bg-background/60 p-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium">
                              {result.user_ids[0] ?? formatFingerprint(result.fingerprint)}
                            </div>
                            <div className="truncate text-xs text-muted-foreground">
                              {result.algorithm} {result.bits ? `• ${result.bits}-bit` : ""}
                            </div>
                          </div>
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => void handleImportKeyserverResult(result.fingerprint)}
                          >
                            Import
                          </Button>
                        </div>
                        <code className="mt-2 block break-all text-xs text-muted-foreground">
                          {result.fingerprint}
                        </code>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
              <DialogFooter className="gap-2">
                <Button
                  variant="ghost"
                  onClick={() => {
                    setIsLookupDialogOpen(false);
                    setLookupQuery("");
                    setKeyserverResults([]);
                  }}
                >
                  Cancel
                </Button>
                <Button variant="secondary" onClick={() => void handleSearchKeyserver()} disabled={!lookupQuery.trim() || isSearchingKeyserver}>
                  {isSearchingKeyserver ? "Searching..." : "Search"}
                </Button>
                <Button onClick={() => void handleLookupKey()} disabled={!lookupQuery.trim()}>
                  Lookup
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
                          <div className="text-sm font-medium">Use Clipboard</div>
                          <div className="text-xs text-muted-foreground">Handle PGP paste shortcuts</div>
                        </div>
                        <Switch checked={useClipboard} onCheckedChange={setUseClipboard} />
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
                      <div className="flex items-center justify-between gap-3 px-2 py-2">
                        <div>
                          <div className="text-sm font-medium">Hide Note Names</div>
                          <div className="text-xs text-muted-foreground">Hides note names on lock</div>
                        </div>
                        <Switch
                          checked={hideNoteNamesOnLock}
                          onCheckedChange={setHideNoteNamesOnLock}
                        />
                      </div>
                      <div className="flex items-center justify-between gap-3 px-2 py-2">
                        <div>
                          <div className="text-sm font-medium">Auto-Show Recipients</div>
                          <div className="text-xs text-muted-foreground">Shows recipients when a note opens</div>
                        </div>
                        <Switch
                          checked={autoShowRecipients}
                          onCheckedChange={setAutoShowRecipients}
                        />
                      </div>
                      <div className="flex items-center justify-between gap-3 px-2 py-2">
                        <div>
                          <div className="text-sm font-medium">Auto-Show PGP Block</div>
                          <div className="text-xs text-muted-foreground">Shows PGP block when a note opens</div>
                        </div>
                        <Switch
                          checked={autoShowPgpBlock}
                          onCheckedChange={setAutoShowPgpBlock}
                        />
                      </div>
                      <div className="flex items-center justify-between gap-3 px-2 py-2">
                        <div>
                          <div className="text-sm font-medium">Show Recent History</div>
                          <div className="text-xs text-muted-foreground">Display the recent activity panel</div>
                        </div>
                        <Switch
                          checked={showRecentHistory}
                          onCheckedChange={setShowRecentHistory}
                        />
                      </div>
                    </DropdownMenuContent>
                  </DropdownMenu>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button size="sm" variant="secondary" className="min-w-[8.5rem] justify-start">
                        <FolderPlus className="h-4 w-4" />
                        Vaults
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" side="bottom" className="w-80">
                      <DropdownMenuLabel>Saved Vaults</DropdownMenuLabel>
                      <DropdownMenuGroup>
                        <DropdownMenuItem onClick={() => void handleBrowseAndSaveVault()}>
                          <FolderPlus className="h-4 w-4" />
                          Save Vault Path...
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={!status.vault_path}
                          onClick={() => handlePinCurrentVault()}
                        >
                          <Pin
                            className={cn(
                              "h-4 w-4",
                              status.vault_path && pinnedVaultPath === status.vault_path && "fill-white text-white",
                            )}
                          />
                          {status.vault_path && pinnedVaultPath === status.vault_path
                            ? "Unpin Current Vault"
                            : "Pin Current Vault"}
                        </DropdownMenuItem>
                      </DropdownMenuGroup>
                      <DropdownMenuSeparator />
                      {savedVaults.length === 0 ? (
                        <DropdownMenuItem disabled>No saved vaults yet</DropdownMenuItem>
                      ) : (
                        savedVaults.map((vault) => (
                          <DropdownMenuItem
                            key={vault.path}
                            className="items-start"
                            onClick={() => void handleOpenSavedVault(vault)}
                            title={vault.path}
                          >
                            <FolderOpen className="mt-0.5 h-4 w-4" />
                            <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                              <span className="truncate font-medium">{vault.label}</span>
                              <span className="truncate text-xs text-muted-foreground">{vault.path}</span>
                            </div>
                            <div className="flex shrink-0 items-center gap-1">
                              {pinnedVaultPath === vault.path ? (
                                <Pin className="h-3.5 w-3.5 fill-white text-white" />
                              ) : null}
                              <Button
                                size="icon"
                                variant="ghost"
                                className="size-7"
                                onClick={(event) => {
                                  event.preventDefault();
                                  event.stopPropagation();
                                  openSaveVaultDialog(vault.path, vault.label);
                                }}
                                aria-label={`Edit ${vault.label}`}
                                title="Edit vault name"
                              >
                                <Pencil className="h-3.5 w-3.5" />
                              </Button>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="size-7 text-muted-foreground hover:text-destructive"
                                onClick={(event) => {
                                  event.preventDefault();
                                  event.stopPropagation();
                                  handleRemoveSavedVault(vault.path);
                                }}
                                aria-label={`Delete ${vault.label}`}
                                title="Delete saved vault"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            </div>
                            {status.vault_path === vault.path ? (
                              <Badge variant="outline" className="shrink-0">Open</Badge>
                            ) : null}
                          </DropdownMenuItem>
                        ))
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button size="sm">
                        <FolderOpen className="h-4 w-4" />
                        Open Vault
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" side="bottom" className="w-40">
                      <DropdownMenuItem onClick={() => void handleOpenFolder()}>
                        Folder
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => void handleOpenArchive()}>
                        Archive
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
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
                <div className="w-full rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">Current Vault Path:</span>{" "}
                  <span className="break-all">{status.vault_path ?? "No vault selected"}</span>
                </div>
                <Badge variant="outline">
                  {status.vault_kind === "archive"
                    ? "Archive vault"
                    : status.vault_kind === "folder"
                    ? "Folder vault"
                    : "No vault"}
                </Badge>
                <Badge variant={status.session_unlocked ? "default" : "secondary"}>
                  {status.session_unlocked ? "Unlocked" : "Locked"}
                </Badge>
                <Badge variant="outline">{notes.length} notes</Badge>
                <Badge variant="outline">{recipientsLabel}</Badge>
                {useSignatureForOutput ? <Badge variant="outline">Signature mode</Badge> : null}
              </div>

              <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_220px]">
                <div className="space-y-3">
                  <Input
                    type="password"
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                    placeholder="Private key passphrase"
                    onKeyDown={(event) => {
                      if (event.key === "Enter" && status.selected_private_key && passphrase) {
                        event.preventDefault();
                        void handleUnlock();
                      }
                    }}
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

          <div className="flex items-center gap-2 rounded-xl border border-border/70 bg-card/60 p-1 backdrop-blur-xl">
            <Button
              variant={activeTab === "vault" ? "secondary" : "ghost"}
              className="flex-1 justify-center"
              onClick={() => setActiveTab("vault")}
            >
              <NotebookPen className="h-4 w-4" />
              Note Vault
            </Button>
            <Button
              variant={activeTab === "files" ? "secondary" : "ghost"}
              className="flex-1 justify-center"
              onClick={() => setActiveTab("files")}
            >
              <Files className="h-4 w-4" />
              Files
            </Button>
            <Button
              variant={activeTab === "keyring" ? "secondary" : "ghost"}
              className="flex-1 justify-center"
              onClick={() => setActiveTab("keyring")}
            >
              <KeyRound className="h-4 w-4" />
              Keyring
            </Button>
          </div>

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

          {activeTab === "vault" ? (
          <div className="grid gap-4 md:grid-cols-[280px_minmax(0,1fr)]">
            <aside className="space-y-4">
              <Card className="border-white/10 bg-card/75">
                <CardHeader className="space-y-3 pb-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <CardTitle className="text-base">Notes</CardTitle>
                    </div>
                    <div className="flex gap-1">
                      <Button variant="ghost" size="icon" onClick={() => void handleRefreshNotes()}>
                        <RefreshCcw className="h-4 w-4" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => void handleCreateFromClipboard()}
                        disabled={status.vault_kind === "none"}
                        aria-label="Decrypt or create note from clipboard"
                        title="Decrypt or create note from clipboard"
                      >
                        <Clipboard className="h-4 w-4" />
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
                            {hideNoteNamesOnLock && !status.session_unlocked ? (
                              <>
                                <div className="truncate text-sm font-medium">Hidden</div>
                                <div className="mt-1 truncate text-xs text-muted-foreground">
                                  Unlock to view note names
                                </div>
                              </>
                            ) : (
                              <>
                                <div className="truncate text-sm font-medium">{note.name}</div>
                                <div className="mt-1 truncate text-xs text-muted-foreground">
                                  {note.relative_path}
                                </div>
                              </>
                            )}
                          </button>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card className="border-white/10 bg-card/75">
                <CardHeader className="space-y-3 pb-3">
                  <div className="flex items-center justify-between gap-2">
                    <CardTitle className="text-base">Keys</CardTitle>
                    <div className="flex items-center gap-2">
                      <Button variant="ghost" size="icon" onClick={() => void refreshKeys()}>
                        <RefreshCcw className="h-4 w-4" />
                      </Button>
                      <label className="flex items-center gap-2 rounded-md border border-border/70 px-2 py-1 text-xs text-muted-foreground">
                        <input
                          type="checkbox"
                          checked={useSignature}
                          onChange={(event) => void handleUseSignatureToggle(event.target.checked)}
                        />
                        <span className="flex flex-col leading-tight">
                          <span>Sign Only</span>
                          <span>(Not Encrypted)</span>
                        </span>
                      </label>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <Button
                      className="w-full"
                      size="sm"
                      variant="secondary"
                      onClick={() => setIsCreateKeyOpen(true)}
                    >
                      <Plus className="h-4 w-4" />
                      Create
                    </Button>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button className="w-full" size="sm" variant="secondary">
                          <FileKey className="h-4 w-4" />
                          Import
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" side="bottom" className="w-36">
                        <DropdownMenuItem onClick={() => void handleImportKey()}>File</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => void handleImportClipboard()}>
                          Clipboard
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 pt-0">
                  <ScrollArea className="h-[340px] pr-3">
                    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleKeyDragEnd}>
                    <SortableContext
                      items={filteredOrderedKeys.map((key) => key.fingerprint)}
                      strategy={verticalListSortingStrategy}
                    >
                    <div className="space-y-2">
                    {filteredOrderedKeys.length === 0 ? (
                        <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                          {keySearch.trim() ? "No keys match this filter." : "No keys imported yet."}
                        </div>
                      ) : (
                        filteredOrderedKeys.map((key) => (
                          <SortableKeyCard
                            key={key.fingerprint}
                            keyItem={key}
                            isPrivatePinned={pinnedPrivateKey === key.fingerprint}
                            isRecipientPinned={pinnedRecipients.includes(key.fingerprint)}
                            onPrivateKeySelection={(fingerprint) => void handlePrivateKeySelection(fingerprint)}
                            onRecipientSelection={(fingerprint, checked) =>
                              void handleRecipientSelection(fingerprint, checked)
                            }
                            onTogglePrivatePin={(currentKey) => void handleTogglePrivatePin(currentKey)}
                            onToggleRecipientPin={(currentKey) => void handleToggleRecipientPin(currentKey)}
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

            <Card className="border-white/10 bg-card/75 md:flex md:min-h-[calc(100vh-12rem)] md:flex-col">
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
                      onClick={() => void handleSaveWithPassword()}
                      disabled={!selectedNote}
                    >
                      <Lock className="h-4 w-4" />
                      Password
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => setShowRecipients((value) => !value)}
                      disabled={!selectedNote}
                    >
                      {showRecipients ? "Hide Recipients" : "Show Recipients"}
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
              <CardContent className="pt-0 md:flex md:flex-1 md:flex-col">
                {selectedNote && showRecipients ? (
                  <div className="mb-3 rounded-xl border border-border/70 bg-background/50 p-3">
                    <div className="flex flex-col gap-2">
                      <div className="text-sm font-medium">Note Recipients</div>
                      <div className="flex flex-wrap gap-2">
                        {useSignatureForOutput ? (
                          <Badge variant="outline">Anyone</Badge>
                        ) : noteEncryptionStatus.recipients.length > 0 ? (
                          noteEncryptionStatus.recipients.map((recipient) => (
                            <Badge
                              key={`${recipient.key_id}-${recipient.fingerprint ?? "unknown"}`}
                              variant={recipient.is_selected_recipient ? "default" : "secondary"}
                            >
                              {recipient.label}
                            </Badge>
                          ))
                        ) : selectedRecipientLabels.length > 0 ? (
                          selectedRecipientLabels.map((recipient) => (
                            <Badge key={recipient.fingerprint} variant="default">
                              {recipient.label}
                            </Badge>
                          ))
                        ) : (
                          <Badge variant="secondary">No recipients detected</Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {useSignatureForOutput
                          ? "Signature mode is not encrypted to specific recipients."
                          : noteEncryptionStatus.can_decrypt_with_selected_key
                          ? "The selected private key matches this note."
                          : "The selected private key does not match this note."}
                      </div>
                      {!useSignatureForOutput && !noteEncryptionStatus.matches_selected_recipients ? (
                        <div className="text-xs text-amber-200">
                          This file is currently encrypted to a different recipient set than the one selected above.
                          Changing recipients re-encrypts the open note immediately.
                        </div>
                      ) : null}
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <Badge variant={signatureBadgeVariant(noteEncryptionStatus.signature.state)}>
                          Signature: {noteEncryptionStatus.signature.state}
                        </Badge>
                        <span>{noteEncryptionStatus.signature.summary}</span>
                      </div>
                    </div>
                  </div>
                ) : null}
                {isPgpPreviewOpen ? (
                  <div className="mb-3 rounded-xl border border-border/70 bg-background/50 p-3">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="text-sm font-medium">PGP Block Preview</div>
                      <div className="flex items-center gap-2">
                        <div className="text-xs text-muted-foreground">
                          {pgpPreviewBusy ? "Updating..." : "Live preview"}
                        </div>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-7"
                          onClick={() => void handleCopyPgpPreview()}
                          disabled={pgpPreviewBusy || !pgpPreview || Boolean(pgpPreviewError)}
                          aria-label="Copy PGP block"
                          title="Copy PGP block"
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </Button>
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
                  className="min-h-[360px] rounded-xl bg-background/70 font-mono text-sm leading-6 md:min-h-0 md:flex-1"
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
          ) : activeTab === "files" ? (
            <div className="grid gap-4 md:grid-cols-[280px_minmax(0,1fr)]">
              <aside className="space-y-4">
                <Card className="border-white/10 bg-card/75 md:flex md:min-h-[calc(100vh-12rem)] md:flex-col">
                  <CardHeader className="space-y-3 pb-3">
                    <div className="flex items-center justify-between gap-2">
                      <CardTitle className="text-base">Keys</CardTitle>
                      <div className="flex items-center gap-2">
                        <Button variant="ghost" size="icon" onClick={() => void refreshKeys()}>
                          <RefreshCcw className="h-4 w-4" />
                        </Button>
                        <label className="flex items-center gap-2 rounded-md border border-border/70 px-2 py-1 text-xs text-muted-foreground">
                          <input
                            type="checkbox"
                            checked={useSignature}
                            onChange={(event) => void handleUseSignatureToggle(event.target.checked)}
                          />
                          <span className="flex flex-col leading-tight">
                            <span>Sign Only</span>
                            <span>(Not Encrypted)</span>
                          </span>
                        </label>
                      </div>
                    </div>
                    <div className="relative">
                      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        className="h-9 pl-9"
                        type="search"
                        value={keySearch}
                        placeholder="Filter keys"
                        onChange={(event) => setKeySearch(event.target.value)}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <Button
                        className="w-full"
                        size="sm"
                        variant="secondary"
                        onClick={() => setIsCreateKeyOpen(true)}
                      >
                        <Plus className="h-4 w-4" />
                        Create
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button className="w-full" size="sm" variant="secondary">
                            <FileKey className="h-4 w-4" />
                            Import
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" side="bottom" className="w-40">
                          <DropdownMenuItem onClick={() => void handleImportKey()}>File</DropdownMenuItem>
                          <DropdownMenuItem onClick={() => void handleImportClipboard()}>
                            Clipboard
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setIsLookupDialogOpen(true)}>
                            Lookup
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4 pt-0 md:flex md:min-h-0 md:flex-1 md:flex-col">
                    <ScrollArea className="h-[340px] pr-3 md:min-h-0 md:flex-1">
                      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleKeyDragEnd}>
                      <SortableContext
                        items={filteredOrderedKeys.map((key) => key.fingerprint)}
                        strategy={verticalListSortingStrategy}
                      >
                      <div className="space-y-2">
                      {filteredOrderedKeys.length === 0 ? (
                          <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                            {keySearch.trim() ? "No keys match this filter." : "No keys imported yet."}
                          </div>
                        ) : (
                          filteredOrderedKeys.map((key) => (
                            <SortableKeyCard
                              key={key.fingerprint}
                              keyItem={key}
                              isPrivatePinned={pinnedPrivateKey === key.fingerprint}
                              isRecipientPinned={pinnedRecipients.includes(key.fingerprint)}
                              onPrivateKeySelection={(fingerprint) => void handlePrivateKeySelection(fingerprint)}
                              onRecipientSelection={(fingerprint, checked) =>
                                void handleRecipientSelection(fingerprint, checked)
                              }
                              onTogglePrivatePin={(currentKey) => void handleTogglePrivatePin(currentKey)}
                              onToggleRecipientPin={(currentKey) => void handleToggleRecipientPin(currentKey)}
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

              <Card className="border-white/10 bg-card/75 md:flex md:min-h-[calc(100vh-12rem)] md:flex-col">
                <CardHeader className="space-y-3 pb-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <CardTitle className="truncate text-base">
                        {selectedFilePaths.length > 0
                          ? `${selectedFilePaths.length} queued item${selectedFilePaths.length === 1 ? "" : "s"}`
                          : "File Workspace"}
                      </CardTitle>
                      <CardDescription>
                        Batch operations, detached signature verification, and recent file outputs.
                      </CardDescription>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <div className="flex rounded-md border border-border/70 bg-background/40 p-1">
                        <Button
                          size="sm"
                          variant={fileCryptoMode === "openpgp" ? "default" : "ghost"}
                          onClick={() => setFileCryptoMode("openpgp")}
                        >
                          OpenPGP
                        </Button>
                        <Button
                          size="sm"
                          variant={fileCryptoMode === "smime" ? "default" : "ghost"}
                          onClick={() => setFileCryptoMode("smime")}
                        >
                          S/MIME
                        </Button>
                      </div>
                      <Button size="sm" onClick={() => void pickFiles()}>
                        <Upload className="h-4 w-4" />
                        Choose Files
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => void pickFolders()}>
                        <FolderOpen className="h-4 w-4" />
                        Choose Folder
                      </Button>
                      <Button size="sm" variant="secondary" onClick={() => void pickOutputDirectory()}>
                        Choose Output Folder
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => void handleVerifyFileSignature()}
                        disabled={!verifyInputPath || !verifySignaturePath}
                      >
                        Verify Signature
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 pt-0 md:flex md:flex-1 md:flex-col">
                  <div
                    className={cn(
                      "rounded-lg border border-dashed p-3 text-sm transition-colors",
                      isFileDropActive
                        ? "border-primary/50 bg-primary/10"
                        : "border-border/70 bg-background/40 text-muted-foreground",
                    )}
                    onDragOver={(event) => {
                      event.preventDefault();
                      setIsFileDropActive(true);
                    }}
                    onDragLeave={() => setIsFileDropActive(false)}
                    onDrop={(event) => void handleFileDrop(event)}
                  >
                    Drop files or folders here or choose them below.
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" onClick={() => void handleEncryptFiles()} disabled={selectedFilePaths.length === 0}>
                      Encrypt
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => void handleDecryptFiles()} disabled={selectedFilePaths.length === 0}>
                      Decrypt
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => void handleSignFiles()} disabled={selectedFilePaths.length === 0}>
                      Sign
                    </Button>
                    <Button size="sm" variant="ghost" onClick={clearSelectedFiles} disabled={selectedFilePaths.length === 0}>
                      Clear
                    </Button>
                  </div>

                  <div className="rounded-xl border border-border/70 bg-background/50 p-3">
                    <div className="mb-2 text-sm font-medium">
                      {fileCryptoMode === "smime" ? "Certificate Recipients" : "File Recipients"}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {fileCryptoMode === "smime" ? (
                        selectedX509RecipientLabels.length > 0 ? (
                          selectedX509RecipientLabels.map((recipient) => (
                            <Badge key={recipient.fingerprint} variant="default">
                              {recipient.label}
                            </Badge>
                          ))
                        ) : (
                          <Badge variant="secondary">No X.509 recipients selected</Badge>
                        )
                      ) : useSignatureForOutput ? (
                        <Badge variant="outline">Anyone</Badge>
                      ) : selectedRecipientLabels.length > 0 ? (
                        selectedRecipientLabels.map((recipient) => (
                          <Badge key={recipient.fingerprint} variant="default">
                            {recipient.label}
                          </Badge>
                        ))
                      ) : (
                        <Badge variant="secondary">No recipients selected</Badge>
                      )}
                    </div>
                    <div className="mt-2 text-xs text-muted-foreground">
                      {fileCryptoMode === "smime"
                        ? selectedX509Recipients.length > 0
                          ? "Selected X.509 certificates will be used for S/MIME encryption."
                          : "Choose one or more X.509 certificates below to encrypt CMS files."
                        : useSignatureForOutput
                        ? "Signature mode is not encrypted to specific recipients."
                        : status.selected_recipients.length > 0
                        ? "Selected recipients will be used for file encryption."
                        : "Choose one or more recipient keys in the left column to encrypt files."}
                    </div>
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-border/70 bg-background/50 p-3">
                      <div className="mb-2 text-sm font-medium">Operation Targets</div>
                      <div className="space-y-2 text-xs text-muted-foreground">
                        <div>
                          Output folder:
                          <div className="mt-1 break-all text-foreground">
                            {fileOutputDir || "Choose an output folder to enable file transforms."}
                          </div>
                        </div>
                        <div className="grid grid-cols-3 gap-2 pt-1">
                          <Badge variant="outline">{selectedFilePaths.length} queued</Badge>
                          <Badge variant="outline">{fileOperationResults.length} recent outputs</Badge>
                          <Badge variant="outline">{status.selected_recipients.length} recipients</Badge>
                        </div>
                      </div>
                    </div>
                    <div className="rounded-xl border border-border/70 bg-background/50 p-3">
                      <div className="mb-2 text-sm font-medium">Verify Detached Signature</div>
                      <div className="space-y-2">
                        <Button size="sm" variant="secondary" onClick={() => void pickVerifyInputFile()}>
                          Choose File
                        </Button>
                        <div className="truncate text-xs text-muted-foreground">
                          {verifyInputPath || "No file selected"}
                        </div>
                        <Button size="sm" variant="secondary" onClick={() => void pickVerifySignatureFile()}>
                          Choose Signature
                        </Button>
                        <div className="truncate text-xs text-muted-foreground">
                          {verifySignaturePath || "No signature selected"}
                        </div>
                        {fileVerificationStatus ? (
                          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                            <Badge variant={signatureBadgeVariant(fileVerificationStatus.state)}>
                              {fileVerificationStatus.state}
                            </Badge>
                            <span>{fileVerificationStatus.summary}</span>
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-4 md:flex-1 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                    <div className="rounded-xl border border-border/70 bg-background/50 p-3 md:flex md:min-h-0 md:flex-col">
                      <div className="mb-2 text-sm font-medium">Queued Files</div>
                      <ScrollArea className="max-h-[320px] pr-3 md:min-h-0 md:flex-1">
                        <div className="space-y-2">
                          {selectedFilePaths.length === 0 ? (
                            <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                              Add files here, then run encrypt, decrypt, or sign.
                            </div>
                          ) : (
                            selectedFilePaths.map((path) => (
                              <div
                                key={path}
                                className="rounded-lg border border-border/70 bg-background/60 px-3 py-2 text-sm"
                              >
                                <div className="truncate font-medium">{filePathLabel(path)}</div>
                                <div className="truncate text-xs text-muted-foreground">{path}</div>
                              </div>
                            ))
                          )}
                        </div>
                      </ScrollArea>
                    </div>

                    <div className="rounded-xl border border-border/70 bg-background/50 p-3 md:flex md:min-h-0 md:flex-col">
                      <div className="mb-2 text-sm font-medium">Recent Outputs</div>
                      <ScrollArea className="max-h-[320px] pr-3 md:min-h-0 md:flex-1">
                        <div className="space-y-2">
                          {fileOperationResults.length === 0 ? (
                            <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                              Completed file operations will appear here.
                            </div>
                          ) : (
                            fileOperationResults.map((result) => (
                              <div
                                key={`${result.input_path}-${result.output_path}`}
                                className="rounded-lg border border-border/70 bg-background/60 px-3 py-2 text-xs text-muted-foreground"
                              >
                                <div className="font-medium text-foreground">{result.operation}</div>
                                <div className="truncate">{result.input_path}</div>
                                <div className="truncate">{result.output_path}</div>
                              </div>
                            ))
                          )}
                        </div>
                      </ScrollArea>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-[320px_minmax(0,1fr)]">
              <aside className="space-y-4">
                <Card className="border-white/10 bg-card/75">
                  <CardHeader className="space-y-3 pb-3">
                    <div className="flex items-center justify-between gap-2">
                      <CardTitle className="text-base">Keyring</CardTitle>
                      <div className="flex items-center gap-2">
                        <Button variant="ghost" size="icon" onClick={() => void refreshKeys()}>
                          <RefreshCcw className="h-4 w-4" />
                        </Button>
                        <label className="flex items-center gap-2 rounded-md border border-border/70 px-2 py-1 text-xs text-muted-foreground">
                          <input
                            type="checkbox"
                            checked={useSignature}
                            onChange={(event) => void handleUseSignatureToggle(event.target.checked)}
                          />
                          <span>Sign only</span>
                        </label>
                      </div>
                    </div>
                    <div className="relative">
                      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        className="h-9 pl-9"
                        type="search"
                        value={keySearch}
                        placeholder="Filter keys"
                        onChange={(event) => setKeySearch(event.target.value)}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <Button size="sm" variant="secondary" onClick={() => setIsCreateKeyOpen(true)}>
                        <Plus className="h-4 w-4" />
                        Create
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button size="sm" variant="secondary">
                            <FileKey className="h-4 w-4" />
                            Import
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" side="bottom" className="w-40">
                          <DropdownMenuItem onClick={() => void handleImportKey()}>File</DropdownMenuItem>
                          <DropdownMenuItem onClick={() => void handleImportClipboard()}>
                            Clipboard
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => setIsLookupDialogOpen(true)}>
                            Lookup
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                      <Button size="sm" variant="secondary" onClick={() => void handleRefreshAllKeys()}>
                        Sync
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0">
                    {latestImportResult ? (
                      <div className="mb-4 rounded-lg border border-border/70 bg-background/40 p-3">
                        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          <Badge variant="outline">{latestImportResult.imported} imported</Badge>
                          <Badge variant="outline">{latestImportResult.unchanged} unchanged</Badge>
                          <Badge variant="outline">{latestImportResult.secret_imported} secret</Badge>
                        </div>
                        <div className="mt-2 text-sm text-muted-foreground">{latestImportResult.summary}</div>
                        {latestImportedKeys.length > 0 ? (
                          <div className="mt-3">
                            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">
                              New Keys
                            </div>
                            <div className="flex flex-wrap gap-2">
                              {latestImportedKeys.map((key) => (
                                <Button
                                  key={key.fingerprint}
                                  size="sm"
                                  variant="secondary"
                                  className="max-w-full justify-start overflow-hidden"
                                  onClick={() => setSelectedKeyFingerprint(key.fingerprint)}
                                >
                                  <span className="truncate">
                                    {key.user_ids[0] ?? formatFingerprint(key.fingerprint)}
                                  </span>
                                </Button>
                              ))}
                            </div>
                          </div>
                        ) : null}
                        {latestUnchangedKeys.length > 0 ? (
                          <div className="mt-3">
                            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">
                              Already Present
                            </div>
                            <div className="flex flex-wrap gap-2">
                              {latestUnchangedKeys.map((key) => (
                                <Button
                                  key={key.fingerprint}
                                  size="sm"
                                  variant="ghost"
                                  className="max-w-full justify-start overflow-hidden"
                                  onClick={() => setSelectedKeyFingerprint(key.fingerprint)}
                                >
                                  <span className="truncate">
                                    {key.user_ids[0] ?? formatFingerprint(key.fingerprint)}
                                  </span>
                                </Button>
                              ))}
                            </div>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                    <ScrollArea className="h-[620px] pr-3">
                      <div className="space-y-2">
                        {filteredOrderedKeys.length === 0 ? (
                          <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                            {keySearch.trim() ? "No keys match this filter." : "No keys imported yet."}
                          </div>
                        ) : (
                        filteredOrderedKeys.map((key) => (
                          <button
                            key={key.fingerprint}
                            className={cn(
                              "w-full rounded-lg border px-3 py-3 text-left transition-colors",
                              selectedKeyFingerprint === key.fingerprint
                                ? "border-primary/40 bg-primary/10"
                                : "border-border/70 bg-background/40 hover:bg-accent",
                            )}
                            onClick={() => setSelectedKeyFingerprint(key.fingerprint)}
                          >
                            <div className="flex items-center justify-between gap-3">
                              <div className="min-w-0">
                                <div className="truncate text-sm font-medium">{key.user_ids[0] ?? "Unnamed key"}</div>
                                <div className="truncate text-xs text-muted-foreground">
                                  {key.algorithm} {key.bits ? `• ${key.bits}-bit` : ""}
                                </div>
                              </div>
                              <Badge variant={key.has_secret ? "default" : "secondary"}>
                                {key.has_secret ? "Secret" : "Public"}
                              </Badge>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                              <code>{formatFingerprint(key.fingerprint)}</code>
                              <span>{key.trust}</span>
                            </div>
                          </button>
                        )))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </aside>

              <div className="space-y-4">
                <Card className="border-white/10 bg-card/75">
                  <CardHeader className="space-y-3 pb-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <CardTitle className="text-base">
                          {selectedKeyDetails?.summary.user_ids[0] ?? selectedKeySummary?.user_ids[0] ?? "Key Details"}
                        </CardTitle>
                        <CardDescription>
                          {selectedKeyDetails?.summary.algorithm ?? selectedKeySummary?.algorithm ?? "OpenPGP"}{" "}
                          {selectedKeyDetails?.summary.bits ?? selectedKeySummary?.bits ?? 0}-bit
                        </CardDescription>
                      </div>
                      {selectedKeySummary ? (
                        <div className="flex flex-wrap gap-2">
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => void handlePrivateKeySelection(selectedKeySummary.fingerprint)}
                            disabled={!selectedKeySummary.has_secret}
                          >
                            Use to decrypt
                          </Button>
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() =>
                              void handleRecipientSelection(
                                selectedKeySummary.fingerprint,
                                !selectedKeySummary.is_selected_recipient,
                              )
                            }
                          >
                            {selectedKeySummary.is_selected_recipient ? "Remove recipient" : "Add recipient"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void handleExportPublic(selectedKeySummary)}
                          >
                            Export Public
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => openExportDialog(selectedKeySummary, "private")}
                            disabled={!selectedKeySummary.has_secret}
                          >
                            Export Secret
                          </Button>
                          <Button size="sm" variant="ghost" onClick={openKeyToolsDialog}>
                            Manage
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void handleRemoveKey(selectedKeySummary)}
                          >
                            Remove
                          </Button>
                        </div>
                      ) : null}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4 pt-0">
                    {isLoadingKeyDetails ? (
                      <div className="rounded-lg border border-border/70 bg-background/40 px-3 py-6 text-sm text-muted-foreground">
                        Loading key details...
                      </div>
                    ) : selectedKeyDetails ? (
                      <>
                        {(() => {
                          const warnings = keyStatusWarnings(selectedKeyDetails.summary);
                          return (
                            <>
                        {latestImportResult ? (
                          <div className="rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-sm text-muted-foreground">
                            <div>{latestImportResult.summary}</div>
                            {latestImportResult.unchanged > 0 ? (
                              <div className="mt-1 text-xs">
                                {latestImportResult.unchanged} matching key
                                {latestImportResult.unchanged === 1 ? " was" : "s were"} already present.
                              </div>
                            ) : null}
                          </div>
                        ) : null}
                        {latestKeyAction &&
                        latestKeyAction.fingerprint === selectedKeyDetails.summary.fingerprint ? (
                          <div className="rounded-lg border border-border/70 bg-background/40 px-3 py-2 text-sm text-muted-foreground">
                            {latestKeyAction.summary}
                          </div>
                        ) : null}
                    <div className="grid gap-3 md:grid-cols-2">
                      <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                        <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Identity</div>
                        <div className="space-y-2 text-sm">
                              {selectedKeyDetails.summary.user_ids.map((userId) => (
                                <div key={userId} className="rounded-md bg-background/60 px-3 py-2">
                                  {userId}
                                </div>
                              ))}
                            </div>
                          </div>
                          <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Status</div>
                            <div className="grid gap-2 text-sm text-muted-foreground">
                              <div>Trust: <span className="text-foreground">{selectedKeyDetails.summary.trust}</span></div>
                              <div>Created: <span className="text-foreground">{formatTimestamp(selectedKeyDetails.summary.created_at)}</span></div>
                              <div>Expires: <span className="text-foreground">{formatTimestamp(selectedKeyDetails.summary.expires_at)}</span></div>
                              <div>Key ID: <code className="text-foreground">{selectedKeyDetails.summary.key_id}</code></div>
                            </div>
                          </div>
                          <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Guidance</div>
                            <div className="space-y-2 text-sm text-muted-foreground">
                              <div>{keyRoleSummary(selectedKeyDetails.summary)}</div>
                              <div>{keyTrustSummary(selectedKeyDetails.summary)}</div>
                              {warnings.length > 0 ? (
                                <div className="rounded-md border border-border/70 bg-background/60 px-3 py-2 text-xs">
                                  {warnings.join(" ")}
                                </div>
                              ) : null}
                            </div>
                          </div>
                        </div>

                        <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                          <div className="mb-2 flex items-center justify-between gap-2">
                            <div className="text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">
                              Hardware Token
                            </div>
                            <div className="flex flex-wrap gap-2">
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() =>
                                  void refreshSmartcardStatus().then((next) => {
                                    if (next) {
                                      recordActivity("key", "Refreshed hardware token status", next.summary);
                                    }
                                  })
                                }
                              >
                                {isLoadingSmartcardStatus ? "Refreshing..." : "Refresh"}
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => void handleRestartSmartcardService()}>
                                Restart Service
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => void handleChangeSmartcardPin()}>
                                Change PIN
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => void handleFetchSmartcardPublicKey()}>
                                Fetch Key
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => void handleCreateSmartcardKeyStubs()}>
                                Sync Stubs
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={smartcardMovableKeyOptions.length === 0}
                                onClick={openSmartcardStoreDialog}
                              >
                                Store Key
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => setIsSmartcardGenerateDialogOpen(true)}>
                                Generate
                              </Button>
                              <Button size="sm" variant="ghost" onClick={() => void handleFactoryResetSmartcard()}>
                                Factory Reset
                              </Button>
                            </div>
                          </div>
                          <div className="space-y-2 text-sm text-muted-foreground">
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge variant={smartcardStatus.available ? "default" : "secondary"}>
                                {smartcardStatus.available ? "Detected" : "Not detected"}
                              </Badge>
                              <span>{smartcardStatus.summary}</span>
                            </div>
                            <div>Reader: <span className="text-foreground">{smartcardStatus.reader ?? "None"}</span></div>
                            <div>Cardholder: <span className="text-foreground">{smartcardStatus.cardholder ?? "Unknown"}</span></div>
                            <div>Serial: <code className="text-foreground">{smartcardStatus.serial_number ?? "Unavailable"}</code></div>
                            {smartcardStatus.available ? (
                              <div className="grid gap-1 text-xs">
                                <div>Sign key: <code className="text-foreground">{smartcardStatus.signature_key ?? "Unavailable"}</code></div>
                                <div>Encrypt key: <code className="text-foreground">{smartcardStatus.encryption_key ?? "Unavailable"}</code></div>
                                <div>Auth key: <code className="text-foreground">{smartcardStatus.authentication_key ?? "Unavailable"}</code></div>
                              </div>
                            ) : null}
                          </div>
                        </div>

                        <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                          <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Capabilities</div>
                          <div className="flex flex-wrap gap-2">
                            {selectedKeyDetails.summary.capabilities.length > 0 ? (
                              selectedKeyDetails.summary.capabilities.map((capability) => (
                                <Badge key={capability} variant="outline">{capability}</Badge>
                              ))
                            ) : (
                              <Badge variant="secondary">No capabilities reported</Badge>
                            )}
                          </div>
                        </div>

                        <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                          <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Fingerprint</div>
                          <code className="block break-all text-sm text-foreground">
                            {selectedKeyDetails.summary.fingerprint}
                          </code>
                        </div>

                        <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                          <div className="mb-3 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Subkeys</div>
                          <div className="space-y-2">
                            {selectedKeyDetails.subkeys.map((subkey) => (
                              <div key={subkey.fingerprint} className="rounded-lg border border-border/70 bg-background/60 p-3">
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <div className="text-sm font-medium">{subkey.algorithm} {subkey.bits ? `• ${subkey.bits}-bit` : ""}</div>
                                  <Badge variant={subkey.has_secret ? "default" : "secondary"}>
                                    {subkey.has_secret ? "Secret available" : "Public only"}
                                  </Badge>
                                </div>
                                <div className="mt-2 text-xs text-muted-foreground">
                                  <code>{subkey.fingerprint}</code>
                                </div>
                                <div className="mt-2 flex flex-wrap gap-2">
                                  {subkey.capabilities.map((capability) => (
                                    <Badge key={`${subkey.fingerprint}-${capability}`} variant="outline">
                                      {capability}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                          <div className="mb-3 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Certifications</div>
                          <div className="space-y-2">
                            {selectedKeyDetails.certifications.length > 0 ? (
                              selectedKeyDetails.certifications.map((certification) => (
                                <div
                                  key={`${certification.signer_key_id}-${certification.created_at ?? 0}-${certification.subject_user_id ?? "key"}`}
                                  className="rounded-lg border border-border/70 bg-background/60 p-3"
                                >
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="min-w-0 text-sm font-medium">
                                      {certification.signer_label}
                                    </div>
                                    <Badge variant={certification.is_self_signature ? "secondary" : "outline"}>
                                      {certification.kind}
                                    </Badge>
                                  </div>
                                  <div className="mt-2 grid gap-1 text-xs text-muted-foreground">
                                    <div>
                                      Signer: <code className="text-foreground">{certification.signer_key_id}</code>
                                    </div>
                                    <div>
                                      Date: <span className="text-foreground">{formatTimestamp(certification.created_at)}</span>
                                    </div>
                                    {certification.subject_user_id ? (
                                      <div>
                                        Subject: <span className="text-foreground">{certification.subject_user_id}</span>
                                      </div>
                                    ) : null}
                                  </div>
                                </div>
                              ))
                            ) : (
                              <div className="rounded-md border border-dashed border-border px-3 py-2 text-sm text-muted-foreground">
                                No certification records were reported for this key.
                              </div>
                            )}
                          </div>
                        </div>
                            </>
                          );
                        })()}
                      </>
                    ) : (
                      <div className="rounded-lg border border-dashed border-border p-6 text-sm text-muted-foreground">
                        Select a key to inspect the keyring.
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card className="border-white/10 bg-card/75">
                  <CardHeader className="space-y-3 pb-3">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <CardTitle className="text-base">X.509 Certificates</CardTitle>
                        <CardDescription>
                          Certificate inventory for CMS / S-MIME workflows.
                        </CardDescription>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Button size="sm" variant="secondary" onClick={() => void refreshX509Certificates()}>
                          Refresh
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => setIsCreateX509DialogOpen(true)}>
                          Create
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => void handleLearnX509Card()}>
                          Learn Card
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => void handleImportX509Certificate()}>
                          Import
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => setIsPasteX509DialogOpen(true)}>
                          Paste
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => void handleImportX509Crl()}>
                          Import CRL
                        </Button>
                        {selectedX509Certificate ? (
                          <Button size="sm" variant="ghost" onClick={() => void handleExportX509Certificate(selectedX509Certificate)}>
                            Export
                          </Button>
                        ) : null}
                        {selectedX509Certificate ? (
                          <Button size="sm" variant="ghost" onClick={() => void handleRefreshX509Validation(selectedX509Certificate)}>
                            Validate
                          </Button>
                        ) : null}
                        {selectedX509Certificate?.has_secret ? (
                          <Button size="sm" variant="ghost" onClick={() => void handleExportX509SecretKey(selectedX509Certificate)}>
                            Export PKCS#12
                          </Button>
                        ) : null}
                        {selectedX509Certificate?.has_secret ? (
                          <Button size="sm" variant="ghost" onClick={() => void handleExportX509SecretKeyP8(selectedX509Certificate)}>
                            Export PKCS#8
                          </Button>
                        ) : null}
                        {selectedX509Certificate?.has_secret ? (
                          <Button size="sm" variant="ghost" onClick={() => void handleChangeX509Passphrase(selectedX509Certificate)}>
                            Change Passphrase
                          </Button>
                        ) : null}
                        {selectedX509Certificate ? (
                          <Button size="sm" variant="ghost" onClick={() => void handleDeleteX509Certificate(selectedX509Certificate)}>
                            Remove
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4 pt-0">
                    {x509Certificates.length === 0 ? (
                      <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                        No X.509 certificates are currently available.
                      </div>
                    ) : (
                      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
                        <ScrollArea className="max-h-[320px] pr-3">
                          <div className="space-y-2">
                            {x509Certificates.map((certificate) => (
                              <button
                                key={certificate.fingerprint}
                                className={cn(
                                  "w-full rounded-lg border px-3 py-3 text-left transition-colors",
                                  selectedX509Fingerprint === certificate.fingerprint
                                    ? "border-primary/40 bg-primary/10"
                                    : "border-border/70 bg-background/40 hover:bg-accent",
                                )}
                                onClick={() => setSelectedX509Fingerprint(certificate.fingerprint)}
                              >
                                <div className="flex items-center justify-between gap-3">
                                  <div className="min-w-0">
                                    <div className="truncate text-sm font-medium">{certificate.subject}</div>
                                    <div className="truncate text-xs text-muted-foreground">
                                      {certificate.algorithm} {certificate.bits ? `• ${certificate.bits}-bit` : ""}
                                    </div>
                                  </div>
                                  <div className="flex flex-wrap items-center justify-end gap-2">
                                    {certificate.is_trusted_root ? (
                                      <Badge variant="outline">Trusted root</Badge>
                                    ) : null}
                                    <Badge variant={certificate.has_secret ? "default" : "secondary"}>
                                      {certificate.has_secret ? "Private" : "Public"}
                                    </Badge>
                                  </div>
                                </div>
                                <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                                  <span>{certificate.validity}</span>
                                  <code>{formatFingerprint(certificate.fingerprint)}</code>
                                </div>
                              </button>
                            ))}
                          </div>
                        </ScrollArea>

                        {selectedX509Certificate ? (
                          <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Certificate Details</div>
                            <div className="grid gap-2 text-sm text-muted-foreground">
                              <div>Subject: <span className="text-foreground">{selectedX509Certificate.subject}</span></div>
                              <div>Issuer: <span className="text-foreground">{selectedX509Certificate.issuer || "Unknown"}</span></div>
                              <div>Validity: <span className="text-foreground">{selectedX509Certificate.validity}</span></div>
                              <div>Trust Root: <span className="text-foreground">{selectedX509Certificate.is_trusted_root ? "Yes" : "No"}</span></div>
                              <div>Serial: <code className="text-foreground">{selectedX509Certificate.serial_number || "Unavailable"}</code></div>
                              <div>Created: <span className="text-foreground">{selectedX509Certificate.created_at ?? "Unknown"}</span></div>
                              <div>Expires: <span className="text-foreground">{selectedX509Certificate.expires_at ?? "None"}</span></div>
                              <div>Key ID: <code className="text-foreground">{selectedX509Certificate.key_id}</code></div>
                              <div>Fingerprint: <code className="break-all text-foreground">{selectedX509Certificate.fingerprint}</code></div>
                            </div>
                            <div className="mt-3 flex flex-wrap gap-2">
                              <Button
                                size="sm"
                                variant="secondary"
                                disabled={!selectedX509Certificate.has_secret}
                                onClick={() => handleX509SignerSelection(selectedX509Certificate.fingerprint)}
                              >
                                {selectedX509SignerFingerprint === selectedX509Certificate.fingerprint
                                  ? "Active signer"
                                  : "Use to sign/decrypt"}
                              </Button>
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={() =>
                                  handleX509RecipientSelection(
                                    selectedX509Certificate.fingerprint,
                                    !selectedX509Recipients.includes(selectedX509Certificate.fingerprint),
                                  )
                                }
                              >
                                {selectedX509Recipients.includes(selectedX509Certificate.fingerprint)
                                  ? "Remove recipient"
                                  : "Add recipient"}
                              </Button>
                              <Button
                                size="sm"
                                variant="secondary"
                                onClick={() =>
                                  void handleSetX509TrustRoot(
                                    selectedX509Certificate,
                                    !selectedX509Certificate.is_trusted_root,
                                  )
                                }
                              >
                                {selectedX509Certificate.is_trusted_root ? "Untrust root" : "Trust root"}
                              </Button>
                            </div>
                            <div className="mt-4 rounded-md border border-border/70 bg-background/60 px-3 py-2 text-xs text-muted-foreground">
                              {x509ValidationSummary(selectedX509Certificate.validity, selectedX509Chain)}
                            </div>
                            <div className="mt-4 rounded-md border border-border/70 bg-background/60 p-3">
                              <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">
                                Trusted Roots
                              </div>
                              <div className="flex flex-wrap gap-2">
                                <Button size="sm" variant="secondary" onClick={() => void handleImportX509Trustlist()}>
                                  Import Snapshot
                                </Button>
                                <Button size="sm" variant="secondary" onClick={() => void handleExportX509Trustlist()}>
                                  Export Snapshot
                                </Button>
                              </div>
                              <div className="mt-2 text-xs text-muted-foreground">
                                Manage trusted root snapshots for this GnuPG profile.
                              </div>
                            </div>
                            <div className="mt-4 rounded-md border border-border/70 bg-background/60 p-3">
                              <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">
                                Certificate Chain
                              </div>
                              {selectedX509Chain ? (
                                <pre className="whitespace-pre-wrap break-words text-xs text-muted-foreground">
                                  {selectedX509Chain}
                                </pre>
                              ) : (
                                <div className="text-xs text-muted-foreground">
                                  No chain information is currently available.
                                </div>
                              )}
                            </div>
                          </div>
                        ) : null}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          )}

          {showRecentHistory ? (
          <Card className="border-white/10 bg-card/75">
            <CardHeader className="space-y-1 pb-3">
              <div className="flex items-center justify-between gap-2">
                <CardTitle className="text-base">Recent Activity</CardTitle>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setIsRecentHistoryOpen((current) => !current)}
                  >
                    {isRecentHistoryOpen ? "Hide Recent History" : "Show Recent History"}
                  </Button>
                  {isRecentHistoryOpen && activityLog.length > 0 ? (
                    <Button size="sm" variant="ghost" onClick={() => setActivityLog([])}>
                      Clear
                    </Button>
                  ) : null}
                </div>
              </div>
              <CardDescription>
                Persistent history for note, file, and key actions on this device.
              </CardDescription>
            </CardHeader>
            {isRecentHistoryOpen ? (
            <CardContent className="pt-0">
              <ScrollArea className="max-h-[220px] pr-3">
                <div className="space-y-2">
                  {activityLog.length === 0 ? (
                    <div className="rounded-lg border border-dashed border-border p-3 text-sm text-muted-foreground">
                      Activity will appear here as you work.
                    </div>
                  ) : (
                    activityLog.map((item) => (
                      <div
                        key={item.id}
                        className="rounded-lg border border-border/70 bg-background/40 px-3 py-2"
                      >
                        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          <Badge variant={activityBadgeVariant(item.kind)}>{item.kind}</Badge>
                          <span>{formatActivityTime(item.at)}</span>
                        </div>
                        <div className="mt-1 text-sm font-medium text-foreground">{item.title}</div>
                        <div className="text-xs text-muted-foreground">{item.detail}</div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
            ) : null}
          </Card>
          ) : null}
        </div>
      </div>
    </div>
  );
}
