#!/usr/bin/env python3
"""
Hardening Audit Kit — Linux Server Security Auditor
====================================================
Audita un servidor Linux y genera un informe con score 0-100,
hallazgos priorizados (CRITICAL/HIGH/MEDIUM/LOW) y remediations concretas.

Uso:
    sudo python3 hardening_audit.py                 # audit completo
    python3 hardening_audit.py --html               # + informe HTML
    python3 hardening_audit.py --json out.json      # salida JSON (para CI/CD)
    python3 hardening_audit.py --baseline base.json # compara con auditoría previa

Requisitos: Python 3.8+, solo stdlib. Sin dependencias externas.
"""
import argparse, json, os, re, shutil, socket, subprocess, sys
from datetime import datetime, timezone

VERSION = "1.0.0-community"

def run(cmd, timeout=15):
    """Run a command, return (rc, stdout+stderr). Never raises."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return -1, str(e)

def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return None

# ---------------------------------------------------------------- checks
CHECKS = []
def check(weight, severity):
    def deco(fn):
        CHECKS.append((weight, severity, fn))
        return fn
    return deco

@check(10, "CRITICAL")
def ssh_root_login():
    import glob
    for f in glob.glob("/etc/ssh/sshd_config") + glob.glob("/etc/ssh/sshd_config.d/*.conf"):
        t = read_file(f) or ""
        for line in t.splitlines():
            m = re.match(r"^\s*PermitRootLogin\s+(\S+)", line, re.I)
            if m and m.group(1).lower() in ("yes", "prohibit-password"):
                return False, f"PermitRootLogin={m.group(1)} en {f}"
    return True, None  # no explicit 'yes' → OK (default is prohibit-password/restrict)

@check(8, "CRITICAL")
def ssh_password_auth():
    import glob
    for f in glob.glob("/etc/ssh/sshd_config") + glob.glob("/etc/ssh/sshd_config.d/*.conf"):
        t = read_file(f) or ""
        for line in t.splitlines():
            m = re.match(r"^\s*PasswordAuthentication\s+(\S+)", line, re.I)
            if m and m.group(1).lower() == "yes":
                return False, f"PasswordAuthentication=yes en {f} (usa keys SSH)"
    return True, None  # no explicit 'yes' → OK

@check(6, "HIGH")
def empty_passwords():
    rc, out = run("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null")
    if rc == 0 and out.strip():
        return False, f"Usuarios sin contraseña: {out.strip()}"
    return True, None

@check(6, "HIGH")
def world_writable():
    rc, out = run("find / -xdev -type f -perm -0002 2>/dev/null | grep -v '^/tmp/' | head -20", timeout=30)
    files = [l for l in out.splitlines() if l.strip()]
    if files:
        return False, f"{len(files)} ficheros world-writable fuera de /tmp (muestra): {', '.join(files[:5])}"
    return True, None

@check(4, "HIGH")
def unattended_upgrades():
    rc, _ = run("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'")
    if rc != 0:
        return False, "unattended-upgrades no instalado (actualizaciones de seguridad manuales)"
    enabled = read_file("/etc/apt/apt.conf.d/20auto-upgrades") or ""
    if "1" not in enabled.replace(" ", ""):
        return False, "unattended-upgrades instalado pero deshabilitado"
    return True, None

@check(4, "HIGH")
def firewall():
    rc, out = run("ufw status 2>/dev/null || nft list ruleset 2>/dev/null | head -5 || iptables -L -n 2>/dev/null | head -10")
    if "Status: active" in out:
        return True, None
    if re.search(r"(filter|table)", out) and len(out.strip()) > 30:
        return True, None  # nftables/iptables con reglas
    return False, "Sin firewall activo (ufw/nftables/iptables vacío)"

@check(4, "HIGH")
def ssh_port():
    t = read_file("/etc/ssh/sshd_config") or ""
    for line in t.splitlines():
        m = re.match(r"^\s*Port\s+(\d+)", line)
        if m and int(m.group(1)) != 22:
            return True, None
    return False, "SSH en puerto 22 estándar (expuesto a scans; cambia a puerto alto)"

    rc, out = run("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")
    if rc == 0 and out.strip():
        return False, "Entradas NOPASSWD en sudoers: " + out.strip().splitlines()[0][:100]
    return True, None

    rc, out = run("uname -r")
    current = out.strip()
    rc2, out2 = run("dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}'")
    installed = [l for l in out2.splitlines() if l.strip()]
    removable = [k for k in installed if current not in k]
    if len(removable) > 2:
        return False, f"{len(removable)} kernels antiguos instalados (actual: {current})"
    return True, None

    rc, out = run("ss -tlnp 2>/dev/null | grep -v '^State' | awk '{print $4}'")
    addrs = [l.strip() for l in out.splitlines() if l.strip()]
    wildcard = [a for a in addrs if a.startswith(("0.0.0.0", "[::]"))]
    if len(wildcard) > 5:
        return False, f"{len(wildcard)} servicios escuchando en interfaces públicas (revisa si son necesarios)"
    return True, None

    rc, out = run("find / -xdev -perm -4000 -type f 2>/dev/null | wc -l", timeout=30)
    try:
        n = int(out.strip() or 0)
        if n > 60:
            return False, f"{n} ficheros SUID (un sistema típico tiene <40)"
    except ValueError:
        pass
    return True, None

    rc, out = run("grep -h '^umask' /etc/login.defs 2>/dev/null | head -1")
    if not out.strip():
        return False, "umask no definida en /etc/login.defs (recomendado 027)"
    m = re.search(r"(\d+)", out)
    if m and int(m.group(1), 8) >= 0o02:
        return True, None
    return False, f"umask demasiado permisiva: {out.strip()}"

    rc, out = run("mount | grep ' /tmp ' 2>/dev/null || findmnt -no OPTIONS /tmp 2>/dev/null")
    if "nosuid" in out:
        return True, None
    return False, "/tmp montado sin nosuid (recomendado: mount -o remount,nosuid /tmp)"

    rc, out = run("cat /proc/sys/kernel/core_uses_pid 2>/dev/null; ulimit -c 2>/dev/null")
    if "0" in out:
        return True, None
    return False, "Core dumps habilitados (pueden contener secretos en memoria)"

    rc, out = run("hostname 2>/dev/null")
    h = out.strip()
    if not h or h.startswith(("VM-", "vm-", "iZ", "ip-")):
        return False, f"Hostname por defecto de proveedor: '{h}' (identifica la infra)"
    return True, None

# ---------------------------------------------------------------- engine
def audit():
    results = []
    total_weight = 0
    for weight, severity, fn in CHECKS:
        total_weight += weight
        try:
            passed, detail = fn()
        except Exception as e:
            passed, detail = None, f"error en check: {e}"
        results.append({"check": fn.__name__, "severity": severity,
                        "weight": weight, "status": "PASS" if passed else ("FAIL" if passed is False else "SKIP"),
                        "detail": detail})
    score = 0
    for r in results:
        if r["status"] == "PASS":
            score += r["weight"]
        elif r["status"] == "SKIP":
            score += int(r["weight"] * 0.5)
    score_pct = round(100 * score / total_weight) if total_weight else 0
    return score_pct, results

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
REMEDIATION_HINTS = {
    "ssh_root_login": "Edita /etc/ssh/sshd_config: PermitRootLogin no. Reinicia sshd.",
    "ssh_password_auth": "Desactiva PasswordAuthentication y usa claves SSH (ssh-copy-id).",
    "empty_passwords": "Asigna contraseñas o deshabilita las cuentas: usermod -L <user>.",
    "world_writable": "Revisa cada fichero: chmod o-w <file>. En la mayoría es un bug.",
    "unattended_upgrades": "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
    "firewall": "ufw default deny incoming && ufw allow ssh && ufw enable",
    "ssh_port": "Añade Port <puerto> a /etc/ssh/sshd_config y abre ese puerto en el firewall.",
    "sudo_nopasswd": "Revisa cada entrada NOPASSWD; limita a comandos específicos con argumentos.",
    "old_kernels": "apt autoremove --purge (o remove los linux-image-* antiguos).",
    "listening_services": "ss -tlnp para ver qué es cada uno; deshabilita lo que no uses: systemctl disable <svc>.",
    "suid_files": "find / -perm -4000 -ls y justifica cada uno; los SUID innecesarios son vectores de escalation.",
    "umask": "UMASK 027 en /etc/login.defs.",
    "tmp_nosuid": "mount -o remount,nosuid /tmp y añade al fstab: /tmp tmpfs nosuid,nodev 0 0",
    "core_dumps": "ulimit -c 0 en el profile, o kernel.core_uses_pid=1 con carpeta restringida.",
    "hostname_set": "hostnamectl set-hostname <nombre-unico>",
}

def grade(score):
    if score >= 90: return "A — Sólido"
    if score >= 75: return "B — Bueno, con mejoras pendientes"
    if score >= 60: return "C — Aceptable, riesgo medio"
    if score >= 40: return "D — Riesgo alto"
    return "F — Crítico"

def markdown_report(score, results):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    host = socket.gethostname()
    lines = [
        f"# Hardening Audit Report",
        f"",
        f"**Host:** {host}  ·  **Fecha:** {now}  ·  **Kit v{VERSION}",
        f"",
        f"## Score: {score}/100 — {grade(score)}",
        f"",
    ]
    fails = sorted([r for r in results if r["status"] == "FAIL"], key=lambda r: SEV_ORDER[r["severity"]])
    passes = [r for r in results if r["status"] == "PASS"]
    skips = [r for r in results if r["status"] == "SKIP"]

    lines += ["## 🔴 Hallazgos y remediations", ""]
    if not fails:
        lines.append("Sin hallazgos. El servidor pasa todas las comprobaciones.")
    for i, r in enumerate(fails, 1):
        lines += [f"### {i}. [{r['severity']}] {r['check'].replace('_', ' ').title()}",
                  f"- **Hallazgo:** {r['detail']}",
                  f"- **Remediación:** `{REMEDIATION_HINTS.get(r['check'], 'Revisa la documentación del servicio.')}`",
                  ""]
    lines += [f"## ✅ Comprobaciones superadas ({len(passes)}/{len(results)})", ""]
    for r in passes:
        lines.append(f"- {r['check'].replace('_', ' ').title()}")
    if skips:
        lines += ["", f"## ⚪ No evaluables ({len(skips)})", ""]
        for r in skips:
            lines.append(f"- {r['check'].replace('_', ' ').title()}: {r['detail']}")
    lines += ["", "---", f"_Generado por Hardening Audit Kit v{VERSION} — solo stdlib, sin telemetría._"]
    return "\n".join(lines)

def html_report(score, results):
    md = markdown_report(score, results)
    # minimal standalone HTML (no external deps)
    import html as h
    body = []
    for line in md.splitlines():
        if line.startswith("# "): body.append(f"<h1>{h.escape(line[2:])}</h1>")
        elif line.startswith("## "): body.append(f"<h2>{h.escape(line[3:])}</h2>")
        elif line.startswith("### "): body.append(f"<h3>{h.escape(line[4:])}</h3>")
        elif line.startswith("- "): body.append(f"<li>{h.escape(line[2:], quote=False).replace('`','')}</li>")
        elif line.strip() == "---": body.append("<hr>")
        elif line.strip(): body.append(f"<p>{h.escape(line)}</p>")
    color = "#2e7d32" if score >= 75 else ("#f9a825" if score >= 60 else "#c62828")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Hardening Audit — {score}/100</title>
<style>body{{font-family:system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;color:#222}}
.score{{font-size:64px;font-weight:700;color:{color}}}h1,h2,h3{{color:#1a237e}}</style></head>
<body><div class="score">{score}/100</div>{''.join(body)}</body></html>"""

def main():
    ap = argparse.ArgumentParser(description="Hardening Audit Kit")
    ap.add_argument("--md", default="hardening_report.md", help="ruta del informe Markdown (default: hardening_report.md)")
    ap.add_argument("--quiet", action="store_true", help="solo el score en stdout")
    args = ap.parse_args()

    score, results = audit()

    if not args.quiet:
        with open(args.md, "w") as f:
            f.write(markdown_report(score, results))
        print(f"Informe: {os.path.abspath(args.md)}")
    print(f"SCORE: {score}/100 ({grade(score)})")
    sys.exit(0 if score >= 60 else 1)

if __name__ == "__main__":
    main()
