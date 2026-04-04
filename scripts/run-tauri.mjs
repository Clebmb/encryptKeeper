import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const cargoBin = path.join(process.env.USERPROFILE ?? "", ".cargo", "bin");
const tauriJs = path.join(repoRoot, "node_modules", "@tauri-apps", "cli", "tauri.js");
const tauriBin =
  process.platform === "win32"
    ? process.execPath
    : path.join(repoRoot, "node_modules", ".bin", "tauri");

if (!existsSync(tauriJs)) {
  console.error("Local Tauri CLI not found. Run `npm install` first.");
  process.exit(1);
}

const env = {
  ...process.env,
  PATH: [cargoBin, process.env.PATH ?? ""].filter(Boolean).join(path.delimiter),
};

function killStaleWindowsDebugBinary() {
  if (process.platform !== "win32") {
    return;
  }

  const debugExe = path.join(repoRoot, "src-tauri", "target", "debug", "encryptkeeper.exe");
  const command = [
    "$target = [System.IO.Path]::GetFullPath($env:ENCRYPTKEEPER_DEBUG_EXE)",
    "$processes = Get-CimInstance Win32_Process -Filter \"Name = 'encryptkeeper.exe'\"",
    "$matches = $processes | Where-Object {",
    "  $_.ExecutablePath -and ([System.IO.Path]::GetFullPath($_.ExecutablePath) -eq $target)",
    "}",
    "foreach ($process in $matches) {",
    "  Stop-Process -Id $process.ProcessId -Force",
    "}",
  ].join("; ");

  const result = spawnSync("powershell.exe", ["-NoProfile", "-Command", command], {
    stdio: "inherit",
    env: {
      ...env,
      ENCRYPTKEEPER_DEBUG_EXE: debugExe,
    },
    shell: false,
  });

  if (typeof result.status === "number" && result.status !== 0) {
    process.exit(result.status);
  }
}

if (["dev", "build"].includes(process.argv[2] ?? "")) {
  killStaleWindowsDebugBinary();
}

const tauriArgs =
  process.platform === "win32" ? [tauriJs, ...process.argv.slice(2)] : process.argv.slice(2);

const result = spawnSync(tauriBin, tauriArgs, {
  stdio: "inherit",
  env,
  shell: false,
});

if (typeof result.status === "number") {
  process.exit(result.status);
}

process.exit(1);
