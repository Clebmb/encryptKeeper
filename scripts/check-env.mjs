import { spawnSync } from "node:child_process";
import path from "node:path";

function resolveCommand(command) {
  if (process.platform !== "win32") {
    return command;
  }
  if (command === "npm") {
    return "npm.cmd";
  }
  if (command === "node") {
    return "node.exe";
  }
  return `${command}.exe`;
}

function windowsGpgCandidates() {
  const roots = [
    process.env.ProgramFiles,
    process.env["ProgramFiles(x86)"],
    process.env.LOCALAPPDATA,
  ].filter(Boolean);

  return roots.flatMap((root) => [
    path.join(root, "GnuPG", "bin", "gpg.exe"),
    path.join(root, "Gpg4win", "bin", "gpg.exe"),
    path.join(root, "Git", "usr", "bin", "gpg.exe"),
  ]);
}

function resolveCheckCommand(command) {
  if (command !== "gpg" || process.platform !== "win32") {
    return resolveCommand(command);
  }

  for (const candidate of windowsGpgCandidates()) {
    const result = spawnSync(candidate, ["--version"], {
      encoding: "utf8",
      stdio: "ignore",
    });
    if (result.status === 0) {
      return candidate;
    }
  }

  return resolveCommand(command);
}

const checks = [
  ["node", ["-v"]],
  ["npm", ["-v"]],
  ["cargo", ["-V"]],
  ["rustc", ["-V"]],
  ["gpg", ["--version"]],
];

let failed = false;

for (const [command, args] of checks) {
  if (command === "npm" && process.env.npm_execpath) {
    const result = spawnSync(process.execPath, [process.env.npm_execpath, ...args], {
      encoding: "utf8",
    });
    if (result.status === 0) {
      console.log(`npm: ${result.stdout.trim().split(/\r?\n/)[0]}`);
      continue;
    }
  }
  const result = spawnSync(resolveCheckCommand(command), args, { encoding: "utf8" });
  if (result.status === 0) {
    const line = `${command}: ${result.stdout.trim().split(/\r?\n/)[0]}`;
    console.log(line);
  } else {
    failed = true;
    console.log(`${command}: missing`);
  }
}

if (failed) {
  process.exitCode = 1;
}
