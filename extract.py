#!/usr/bin/env python3
"""Hermes Watchdog — Extractor de métricas del VPS para dashboard.

Ejecutar en VPS: docker cp state.db → análisis → data.json → git push.
Detección de anomalías: sesiones múltiples, tasa de tokens, sesiones huérfanas.
Alertas Telegram con deduplicación (no spamear mismo incidente cada 2h).
"""

import sqlite3
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# === CONFIG ===
DB_PATH = "/tmp/state.db"          # cp desde container
OUTPUT_JSON = "/tmp/data.json"
ALERTS_STATE = "/tmp/hermes_alerts_state.json"
REPO_DIR = os.path.expanduser("~/hermes-dashboard")
GITHUB_REPO = "git@github.com:cacarotmaster/hermes-dashboard.git"
TELEGRAM_ENV_FILE = os.path.expanduser("~/.hermes/.env")
IMAGE_COUNTER_FILE = "/opt/data/image_counter.json"  # contador de imágenes por perfil

# Umbrales de alerta
MAX_SESSIONS_SAME_USER = 2          # ≥3 → alerta crítica
MAX_SESSIONS_SAME_GATEWAY = 5       # ≥6 → advertencia
TOKEN_RATE_MULTIPLIER = 2.0         # >2× la media → alerta
ORPHAN_SESSION_HOURS = 24           # >24h sin actividad
ALERT_COOLDOWN_HOURS = 6            # no reenviar misma alerta antes de 6h

# Fecha de inicio: solo contar datos desde esta fecha (medianoche Colombia = UTC-5)
# Cambiar a None para contar todo el histórico
SINCE_DATE = datetime.now(timezone.utc).replace(hour=5, minute=0, second=0, microsecond=0)
# Si ya pasó la medianoche UTC-5, usar la de hoy; si no, la de ayer
if SINCE_DATE > datetime.now(timezone.utc):
    SINCE_DATE = SINCE_DATE - timedelta(days=1)
SINCE_TS = SINCE_DATE.timestamp()

# Mapeo user_id → nombre perfil (detectado de gateway routing)
USER_PROFILE_MAP = {}  # se llena dinámicamente


def load_telegram_creds():
    """Carga TELEGRAM_BOT_TOKEN y TELEGRAM_HOME_CHANNEL desde .env."""
    creds = {}
    if os.path.exists(TELEGRAM_ENV_FILE):
        with open(TELEGRAM_ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_HOME_CHANNEL"):
                    creds[k] = v
    return creds


def get_system_health():
    """Salud extendida: uptime, load, procesos, swap detalle."""
    health = {"uptime": "", "load": {}, "processes": 0, "swap_percent": 0}

    # Uptime
    try:
        with open("/proc/uptime") as f:
            uptime_s = float(f.read().split()[0])
        days = int(uptime_s // 86400)
        hours = int((uptime_s % 86400) // 3600)
        health["uptime"] = f"{days}d {hours}h"
    except Exception:
        health["uptime"] = "N/A"

    # Load average
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        health["load"] = {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    except Exception:
        health["load"] = {}

    # Process count
    try:
        health["processes"] = len(os.listdir("/proc")) - len(
            [p for p in os.listdir("/proc") if not p.isdigit()]
        )
    except Exception:
        health["processes"] = 0

    # Swap %
    try:
        out = subprocess.check_output(["free", "-b"], text=True)
        lines = out.strip().split("\n")
        if len(lines) > 2:
            sw = lines[2].split()
            if int(sw[1]) > 0:
                health["swap_percent"] = round(int(sw[2]) / int(sw[1]) * 100, 1)
    except Exception:
        pass

    return health


def get_system_metrics():
    """RAM y disco del VPS."""
    metrics = {"ram": {}, "disk": {}, "docker": {}}

    # RAM
    try:
        out = subprocess.check_output(["free", "-b"], text=True)
        lines = out.strip().split("\n")
        mem = lines[1].split()
        metrics["ram"] = {
            "total_gb": round(int(mem[1]) / 1e9, 1),
            "used_gb": round(int(mem[2]) / 1e9, 1),
            "free_gb": round(int(mem[3]) / 1e9, 1),
            "available_gb": round(int(mem[6]) / 1e9, 1),
            "percent": round(int(mem[2]) / int(mem[1]) * 100, 1),
        }
        # Swap
        if len(lines) > 2:
            sw = lines[2].split()
            metrics["ram"]["swap_total_gb"] = round(int(sw[1]) / 1e9, 1)
            metrics["ram"]["swap_used_gb"] = round(int(sw[2]) / 1e9, 1)
    except Exception as e:
        metrics["ram"]["error"] = str(e)

    # Disco
    try:
        out = subprocess.check_output(["df", "-B1", "/"], text=True)
        lines = out.strip().split("\n")
        parts = lines[1].split()
        metrics["disk"] = {
            "total_gb": round(int(parts[1]) / 1e9, 1),
            "used_gb": round(int(parts[2]) / 1e9, 1),
            "free_gb": round(int(parts[3]) / 1e9, 1),
            "percent": int(parts[4].replace("%", "")),
        }
    except Exception as e:
        metrics["disk"]["error"] = str(e)

    # Docker stats
    try:
        out = subprocess.check_output(
            ["docker", "stats", "--no-stream",
             "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"],
            text=True
        )
        for line in out.strip().split("\n"):
            name, cpu, mem_usage, mem_perc = line.split("\t")
            metrics["docker"][name] = {
                "cpu": cpu,
                "mem": mem_usage,
                "mem_percent": mem_perc,
            }
    except Exception as e:
        metrics["docker"]["error"] = str(e)

    return metrics


def load_state_db():
    """Copia state.db del container y conecta."""
    # Si ya existe en /tmp, verificar que no sea viejo
    subprocess.run(
        ["docker", "cp", "hermes:/opt/data/state.db", DB_PATH],
        capture_output=True, timeout=15
    )
    if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
        raise RuntimeError("No se pudo copiar state.db")
    return sqlite3.connect(DB_PATH)


def get_profile_metrics(conn):
    """Métricas por perfil Telegram: tokens, sesiones, modelos, proyección."""
    c = conn.cursor()

    # Mapeo user_id → display_name desde gateway_routing
    # También mapeo inverso: display_name → user_id
    user_labels = {}
    name_to_uid = {}
    try:
        c.execute("SELECT entry_json FROM gateway_routing")
        for (entry_json,) in c.fetchall():
            try:
                entry = json.loads(entry_json)
                sk = entry.get("session_key", "")
                uid = entry.get("user_id", "")
                dn = entry.get("display_name", "")
                if "telegram" in sk:
                    if not uid and "telegram:dm:" in sk:
                        uid = sk.split("telegram:dm:")[-1]
                    if uid:
                        user_labels[str(uid)] = dn
                        if dn:
                            name_to_uid[dn] = str(uid)
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    # Perfiles esperados: todos los gateways configurados en el VPS
    expected_profiles = [
        {"user_id": name_to_uid.get("Cacarot", "2079556774"), "label": "Carlos", "bot": "default"},
        {"user_id": name_to_uid.get("Mari", "8916742032"), "label": "Mari", "bot": "mari"},
        {"user_id": name_to_uid.get("Piedad", ""), "label": "Piedad", "bot": "piedad"},
        {"user_id": name_to_uid.get("Cielo", ""), "label": "Cielo", "bot": "cielo"},
        {"user_id": name_to_uid.get("Neffer", ""), "label": "Neffer", "bot": "neffer"},
    ]

    # Solo perfiles Telegram
    c.execute("""
        SELECT
            s.user_id,
            s.source,
            COUNT(DISTINCT sm.session_id) as sessions,
            SUM(sm.api_call_count) as calls,
            SUM(sm.input_tokens + sm.output_tokens
                + COALESCE(sm.cache_read_tokens, 0)
                + COALESCE(sm.reasoning_tokens, 0)) as total_tok,
            SUM(sm.estimated_cost_usd) as est_cost,
            AVG(sm.input_tokens + sm.output_tokens
                + COALESCE(sm.cache_read_tokens, 0)
                + COALESCE(sm.reasoning_tokens, 0)) as avg_tok_per_session,
            MIN(sm.first_seen) as first_activity,
            MAX(sm.last_seen) as last_activity
        FROM session_model_usage sm
        JOIN sessions s ON sm.session_id = s.id
        WHERE s.source = 'telegram'
          AND sm.first_seen >= ?
        GROUP BY s.user_id
        ORDER BY total_tok DESC
    """, (SINCE_TS,))

    # Construir datos reales indexados por user_id
    real_data = {}
    now = time.time()
    for row in c.fetchall():
        uid, source, sessions_n, calls, total_tok, est_cost, avg_tok, first, last = row
        uid_str = str(uid) if uid else "anon"

        if first and total_tok:
            days_active = max(1, (now - first) / 86400)
            tok_per_day = total_tok / days_active
            tok_month_est = tok_per_day * 30
        else:
            tok_per_day = 0
            tok_month_est = 0

        real_data[uid_str] = {
            "sessions": sessions_n, "calls": calls or 0,
            "total_tokens": total_tok or 0,
            "avg_tokens_per_session": int(avg_tok or 0),
            "tokens_per_day": int(tok_per_day),
            "projected_monthly_tokens": int(tok_month_est),
            "estimated_cost_usd": round(est_cost or 0, 4),
            "first_activity_iso": datetime.fromtimestamp(first, tz=timezone.utc).isoformat() if first else None,
            "last_activity_iso": datetime.fromtimestamp(last, tz=timezone.utc).isoformat() if last else None,
            "days_active": round(max(1, now - first) / 86400, 1) if first else 0,
        }

    # Modelo favorito por user_id
    c.execute("""
        SELECT s.user_id, sm.model, sm.billing_provider,
               SUM(sm.input_tokens + sm.output_tokens
                   + COALESCE(sm.cache_read_tokens, 0)
                   + COALESCE(sm.reasoning_tokens, 0)) as total_tok
        FROM session_model_usage sm
        JOIN sessions s ON sm.session_id = s.id
        WHERE s.source = 'telegram'
          AND sm.first_seen >= ?
        GROUP BY s.user_id, sm.model, sm.billing_provider
        ORDER BY total_tok DESC
    """, (SINCE_TS,))
    fav_models = {}
    for uid, model, provider, tok in c.fetchall():
        uid_str = str(uid) if uid else "anon"
        if uid_str not in fav_models:
            fav_models[uid_str] = {"model": model, "provider": provider, "tokens": tok}

    # Cargar contador de imágenes
    image_counts = {}
    if os.path.exists(IMAGE_COUNTER_FILE):
        try:
            with open(IMAGE_COUNTER_FILE) as f:
                image_counts = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    # Fusionar perfiles esperados + datos reales
    profiles = []
    for ep in expected_profiles:
        uid = ep["user_id"] or ""
        label = ep["label"]
        rd = real_data.get(uid, {})

        fm = fav_models.get(uid)
        profile = {
            "user_id": uid or f"pending_{label.lower()}",
            "label": label,
            "bot": ep["bot"],
            "source": "telegram",
            "sessions": rd.get("sessions", 0),
            "calls": rd.get("calls", 0),
            "total_tokens": rd.get("total_tokens", 0),
            "avg_tokens_per_session": rd.get("avg_tokens_per_session", 0),
            "tokens_per_day": rd.get("tokens_per_day", 0),
            "projected_monthly_tokens": rd.get("projected_monthly_tokens", 0),
            "estimated_cost_usd": rd.get("estimated_cost_usd", 0),
            "first_activity_iso": rd.get("first_activity_iso"),
            "last_activity_iso": rd.get("last_activity_iso"),
            "days_active": rd.get("days_active", 0),
            "favorite_model": fm["model"] if fm else "—",
            "favorite_provider": fm["provider"] if fm else "—",
            "image_count": image_counts.get(uid, 0),
            "active": rd.get("total_tokens", 0) > 0,
        }
        profiles.append(profile)

    return profiles


def get_model_metrics(conn):
    """Ranking de LLMs por uso."""
    c = conn.cursor()
    c.execute("""
        SELECT
            sm.model,
            sm.billing_provider,
            COUNT(DISTINCT sm.session_id) as sessions,
            SUM(sm.api_call_count) as calls,
            SUM(sm.input_tokens) as input_tok,
            SUM(sm.output_tokens) as output_tok,
            SUM(sm.cache_read_tokens) as cache_read,
            SUM(sm.reasoning_tokens) as reasoning,
            SUM(sm.estimated_cost_usd) as est_cost
        FROM session_model_usage sm
        WHERE sm.first_seen >= ?
        GROUP BY sm.model, sm.billing_provider
        ORDER BY input_tok + output_tok + COALESCE(cache_read, 0) + COALESCE(reasoning, 0) DESC
    """, (SINCE_TS,))

    models = []
    grand_total = 0
    for row in c.fetchall():
        model, provider, sessions_n, calls, inp, out, cache, reason, cost = row
        total = (inp or 0) + (out or 0) + (cache or 0) + (reason or 0)
        grand_total += total
        models.append({
            "model": model,
            "provider": provider,
            "sessions": sessions_n,
            "calls": calls or 0,
            "input_tokens": inp or 0,
            "output_tokens": out or 0,
            "cache_read_tokens": cache or 0,
            "reasoning_tokens": reason or 0,
            "total_tokens": total,
            "estimated_cost_usd": round(cost or 0, 4),
        })

    # Calcular porcentajes
    for m in models:
        m["percent"] = round(m["total_tokens"] / grand_total * 100, 1) if grand_total > 0 else 0

    return models, grand_total


def detect_anomalies(conn, profiles):
    """Detecta anomalías: sesiones múltiples, tasa inusual, huérfanas."""
    c = conn.cursor()
    alerts = []
    now = time.time()

    # 1. Sesiones simultáneas por user_id (últimas 2 horas)
    two_hours_ago = now - 7200
    c.execute("""
        SELECT s.user_id, s.source, COUNT(*) as active_sessions,
               GROUP_CONCAT(sm.session_id) as session_list
        FROM session_model_usage sm
        JOIN sessions s ON sm.session_id = s.id
        WHERE sm.last_seen > ?
          AND s.source = 'telegram'
        GROUP BY s.user_id
        HAVING COUNT(*) >= ?
    """, (two_hours_ago, MAX_SESSIONS_SAME_USER + 1))

    for uid, source, count, session_list in c.fetchall():
        uid_str = str(uid) if uid else "anon"
        label = USER_PROFILE_MAP.get(uid_str, uid_str)
        alerts.append({
            "type": "multi_session_user",
            "severity": "critical",
            "profile": label,
            "user_id": uid_str,
            "source": source,
            "message": f"{label} tiene {count} sesiones activas simultáneas (umbral: {MAX_SESSIONS_SAME_USER})",
            "details": {
                "active_sessions": count,
                "threshold": MAX_SESSIONS_SAME_USER,
                "session_ids": session_list.split(",") if session_list else [],
            },
        })

    # 2. Sesiones simultáneas por gateway (todos los user_id de telegram)
    c.execute("""
        SELECT COUNT(DISTINCT sm.session_id) as total_sessions,
               GROUP_CONCAT(DISTINCT s.user_id) as users
        FROM session_model_usage sm
        JOIN sessions s ON sm.session_id = s.id
        WHERE sm.last_seen > ?
          AND s.source = 'telegram'
    """, (two_hours_ago,))
    row = c.fetchone()
    if row and row[0] and row[0] > MAX_SESSIONS_SAME_GATEWAY:
        alerts.append({
            "type": "multi_session_gateway",
            "severity": "warning",
            "profile": "all",
            "message": f"Gateway Telegram: {row[0]} sesiones activas totales (umbral: {MAX_SESSIONS_SAME_GATEWAY})",
            "details": {
                "active_sessions": row[0],
                "threshold": MAX_SESSIONS_SAME_GATEWAY,
                "users": row[1].split(",") if row[1] else [],
            },
        })

    # 3. Tasa de tokens inusual (última hora vs media 7 días)
    one_hour_ago = now - 3600
    seven_days_ago = now - 604800

    for p in profiles:
        if p["source"] != "telegram" or p["days_active"] < 1:
            continue

        # Tokens en la última hora
        c.execute("""
            SELECT SUM(sm.input_tokens + sm.output_tokens
                       + COALESCE(sm.cache_read_tokens, 0)
                       + COALESCE(sm.reasoning_tokens, 0))
            FROM session_model_usage sm
            JOIN sessions s ON sm.session_id = s.id
            WHERE s.user_id = ? AND sm.last_seen > ?
        """, (p["user_id"], one_hour_ago))
        last_hour = c.fetchone()[0] or 0

        # Media de tokens/hora últimos 7 días
        c.execute("""
            SELECT SUM(sm.input_tokens + sm.output_tokens
                       + COALESCE(sm.cache_read_tokens, 0)
                       + COALESCE(sm.reasoning_tokens, 0))
            FROM session_model_usage sm
            JOIN sessions s ON sm.session_id = s.id
            WHERE s.user_id = ? AND sm.last_seen > ?
        """, (p["user_id"], seven_days_ago))
        week_tokens = c.fetchone()[0] or 0
        avg_hourly = week_tokens / (7 * 24) if week_tokens > 0 else 0

        if last_hour > avg_hourly * TOKEN_RATE_MULTIPLIER and avg_hourly > 1000:
            alerts.append({
                "type": "token_rate_spike",
                "severity": "warning",
                "profile": p["label"],
                "user_id": p["user_id"],
                "message": (
                    f"{p['label']}: {last_hour/1e6:.1f}M tokens en la última hora "
                    f"(media: {avg_hourly/1e6:.2f}M/h, {last_hour/avg_hourly:.1f}×)"
                ),
                "details": {
                    "tokens_last_hour": last_hour,
                    "avg_hourly_tokens": int(avg_hourly),
                    "multiplier": round(last_hour / avg_hourly, 1) if avg_hourly > 0 else 0,
                },
            })

    # 4. Sesiones huérfanas (>24h sin actividad)
    orphan_cutoff = now - ORPHAN_SESSION_HOURS * 3600
    c.execute("""
        SELECT s.user_id, s.source, sm.session_id,
               datetime(sm.last_seen, 'unixepoch') as last_seen_str
        FROM session_model_usage sm
        JOIN sessions s ON sm.session_id = s.id
        WHERE sm.last_seen < ? AND sm.last_seen > 0
          AND s.source = 'telegram'
        ORDER BY sm.last_seen DESC
        LIMIT 10
    """, (orphan_cutoff,))
    orphans = c.fetchall()
    if orphans:
        orphan_list = [
            {"user_id": str(uid) if uid else "anon", "session_id": sid, "last_seen": ls}
            for uid, _, sid, ls in orphans
        ]
        alerts.append({
            "type": "orphan_sessions",
            "severity": "info",
            "profile": "all",
            "message": f"{len(orphans)} sesiones sin actividad >{ORPHAN_SESSION_HOURS}h",
            "details": {"count": len(orphans), "sessions": orphan_list[:5]},
        })

    return alerts


def send_telegram_alert(alerts, creds):
    """Envía alertas por Telegram con deduplicación. Solo alertas nuevas/no notificadas."""
    if not creds.get("TELEGRAM_BOT_TOKEN") or not creds.get("TELEGRAM_HOME_CHANNEL"):
        print("  ⚠️ Sin credenciales Telegram, omitiendo notificación")
        return

    token = creds["TELEGRAM_BOT_TOKEN"]
    chat_id = creds["TELEGRAM_HOME_CHANNEL"]

    # Cargar estado de alertas previas
    state = {}
    if os.path.exists(ALERTS_STATE):
        with open(ALERTS_STATE) as f:
            state = json.load(f)

    new_alerts = []
    now_ts = time.time()
    cooldown = ALERT_COOLDOWN_HOURS * 3600

    for alert in alerts:
        # Clave única: tipo + perfil + user_id
        key = f"{alert['type']}:{alert.get('profile','')}:{alert.get('user_id','')}"
        last_sent = state.get(key, 0)
        if now_ts - last_sent > cooldown:
            new_alerts.append(alert)
            state[key] = now_ts

    if not new_alerts:
        print(f"  📵 Sin alertas nuevas (cooldown activo para {len(alerts)} existentes)")
        return

    # Construir mensaje
    sev_emoji = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
    lines = ["⚡ *HERMES WATCHDOG — Alertas*", ""]
    for a in new_alerts:
        emoji = sev_emoji.get(a["severity"], "⚪")
        lines.append(f"{emoji} *{a['severity'].upper()}* — {a['message']}")
    lines.append("")
    lines.append(f"🔗 [Dashboard](https://cacarotmaster.github.io/hermes-dashboard)")

    message = "\n".join(lines)

    # Enviar
    try:
        import urllib.request
        import urllib.parse
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": "true",
        }).encode()
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                print(f"  ✅ Telegram: {len(new_alerts)} alertas enviadas")
                # Guardar estado actualizado
                with open(ALERTS_STATE, "w") as f:
                    json.dump(state, f)
            else:
                print(f"  ❌ Telegram error: {result}")
    except Exception as e:
        print(f"  ❌ Telegram falló: {e}")


def git_push():
    """Commit y push de data.json al repo de GitHub Pages."""
    if not os.path.isdir(REPO_DIR):
        subprocess.run(
            ["git", "clone", GITHUB_REPO, REPO_DIR],
            check=True, timeout=30
        )

    # Asegurar git config
    subprocess.run(
        ["git", "config", "user.email", "hermes@watchdog.local"],
        cwd=REPO_DIR
    )
    subprocess.run(
        ["git", "config", "user.name", "Hermes Watchdog"],
        cwd=REPO_DIR
    )

    # Copiar data.json al repo
    dest = os.path.join(REPO_DIR, "data.json")
    subprocess.run(["cp", OUTPUT_JSON, dest], check=True)

    # Commit y push
    os.chdir(REPO_DIR)
    subprocess.run(["git", "add", "data.json"], check=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    result = subprocess.run(
        ["git", "commit", "-m", f"📊 Métricas {ts}"],
        capture_output=True, text=True
    )
    # Ignorar "nothing to commit" — es normal si no hay cambios
    if result.returncode != 0 and "nothing to commit" not in result.stdout + result.stderr:
        print(f"  ⚠️ Git commit: {result.stderr.strip()}")

    subprocess.run(
        ["git", "push", "origin", "main"],
        check=True, timeout=30
    )
    print(f"  🚀 Push exitoso → {ts}")


def main():
    print("🔍 Hermes Watchdog — Extractor de métricas")
    print(f"   {datetime.now().isoformat()}")

    # 1. Cargar credenciales Telegram
    creds = load_telegram_creds()
    print(f"   Telegram: {'✅ configurado' if creds.get('TELEGRAM_BOT_TOKEN') else '❌ sin token'}")

    # 2. Cargar state.db
    print("   📂 Cargando state.db...")
    conn = load_state_db()
    print(f"   ✅ state.db: {os.path.getsize(DB_PATH)/1e6:.1f} MB")

    # 3. Métricas de sistema
    print("   🖥️  Métricas de sistema...")
    system = get_system_metrics()

    # 4. Métricas de perfiles
    print("   👤 Métricas de perfiles...")
    profiles = get_profile_metrics(conn)

    # 5. Métricas de modelos
    print("   🤖 Métricas de modelos...")
    models, grand_total_tokens = get_model_metrics(conn)

    # 6. Detección de anomalías
    print("   🔍 Detectando anomalías...")
    alerts = detect_anomalies(conn, profiles)

    # 7. Proyección a 6 perfiles (solo Telegram)
    active_profiles = [p for p in profiles if p["tokens_per_day"] > 0]
    avg_daily_tokens = (
        sum(p["tokens_per_day"] for p in active_profiles) / len(active_profiles)
        if active_profiles else 0
    )
    projection = {
        "current_profiles": len(active_profiles),
        "target_profiles": 6,
        "avg_daily_tokens_per_profile": int(avg_daily_tokens),
        "projected_monthly_tokens": int(avg_daily_tokens * 30 * 6),
        "projected_daily_tokens": int(avg_daily_tokens * 6),
        "growth_margin_percent": 15,
        "with_margin_monthly": int(avg_daily_tokens * 30 * 6 * 1.15),
    }

    # 8. Salud del sistema extendida
    system_health = get_system_health()

    # 9. Generar data.json
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_at_unix": time.time(),
        "update_interval_minutes": 120,
        "since_date": SINCE_DATE.isoformat(),
        "since_ts": SINCE_TS,
        "system": system,
        "system_health": system_health,
        "profiles": profiles,
        "models": models,
        "grand_total_tokens": grand_total_tokens,
        "grand_total_sessions": sum(p["sessions"] for p in profiles),
        "grand_total_calls": sum(p["calls"] for p in profiles),
        "projection": projection,
        "alerts": alerts,
        "alerts_count": len(alerts),
        "alerts_by_severity": {
            "critical": len([a for a in alerts if a["severity"] == "critical"]),
            "warning": len([a for a in alerts if a["severity"] == "warning"]),
            "info": len([a for a in alerts if a["severity"] == "info"]),
        },
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"   📄 data.json generado: {os.path.getsize(OUTPUT_JSON)/1024:.1f} KB")

    # 9. Alertas Telegram
    if alerts:
        print(f"   🚨 {len(alerts)} anomalías detectadas")
        for a in alerts:
            print(f"      {a['severity']}: {a['message'][:100]}")
        send_telegram_alert(alerts, creds)
    else:
        print("   ✅ Sin anomalías detectadas")

    # 10. Git push
    print("   📤 Git push...")
    try:
        git_push()
    except Exception as e:
        print(f"   ⚠️ Git push falló: {e}")
        print("   (data.json generado en /tmp, se intentará en próxima ejecución)")

    conn.close()
    print("✅ Extracción completa")


if __name__ == "__main__":
    main()
