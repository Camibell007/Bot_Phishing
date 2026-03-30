import requests
import urllib3
import time
import os
import sys
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from threading import Lock

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TZ_COLOMBIA = timezone(timedelta(hours=-5))


def hora_colombia():
    return datetime.now(TZ_COLOMBIA).strftime("%Y-%m-%d %H:%M:%S")


# -----------------------------
# Configuración desde variables de entorno
# -----------------------------
TOKEN = os.getenv("MONITOR_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

if not TOKEN:
    print("ERROR: La variable de entorno MONITOR_TOKEN no está definida.", flush=True)
    sys.exit(1)

if not CHAT_ID:
    print("ERROR: La variable de entorno TELEGRAM_CHAT_ID no está definida.", flush=True)
    sys.exit(1)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "logs")
os.makedirs(_LOGS_DIR, exist_ok=True)

DB_FILE = os.path.join(_LOGS_DIR, "procesados.db")
ALERT_LOG = os.path.join(_LOGS_DIR, "alertas_monitor.log")
YARA_RULES_FILE = os.path.join(_BASE_DIR, "regla.yara")

OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.csv"

HEADERS_WEB = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}

NUM_WORKERS = 15
DOWNLOAD_TO = 6
CYCLE_SLEEP = 300
DB_MAX_URLS = 100_000
CLEANUP_EVERY = 20

_analysis_session = requests.Session()
_analysis_session.headers.update(HEADERS_WEB)
_analysis_session.verify = False

_feed_session = requests.Session()
_feed_session.headers.update({"User-Agent": "Mozilla/5.0"})

_db_lock = Lock()


def init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS procesadas ("
        "  url TEXT PRIMARY KEY,"
        "  ts  TEXT NOT NULL"
        ")"
    )
    conn.commit()
    return conn


def url_procesada(conn: sqlite3.Connection, url: str) -> bool:
    with _db_lock:
        return (
            conn.execute("SELECT 1 FROM procesadas WHERE url=?", (url,)).fetchone()
            is not None
        )


def marcar_procesada(conn: sqlite3.Connection, url: str):
    with _db_lock:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO procesadas (url, ts) VALUES (?, ?)",
                (url, hora_colombia()),
            )
            conn.commit()
        except Exception:
            pass


def total_procesadas(conn: sqlite3.Connection) -> int:
    with _db_lock:
        return conn.execute("SELECT COUNT(*) FROM procesadas").fetchone()[0]


def limpiar_db(conn: sqlite3.Connection):
    with _db_lock:
        count = conn.execute("SELECT COUNT(*) FROM procesadas").fetchone()[0]
        if count > DB_MAX_URLS:
            exceso = count - DB_MAX_URLS
            conn.execute(
                "DELETE FROM procesadas WHERE url IN ("
                "  SELECT url FROM procesadas ORDER BY ts ASC LIMIT ?"
                ")",
                (exceso,),
            )
            conn.commit()
            print(
                f"[DB] Limpieza: eliminados {exceso} registros | total={DB_MAX_URLS}",
                flush=True,
            )


# -------------------------------------------------------
# YARA
# -------------------------------------------------------
try:
    import yara

    if os.path.exists(YARA_RULES_FILE):
        rules = yara.compile(filepath=YARA_RULES_FILE)
        YARA_OK = True
        print("[Monitor] YARA activo ✓", flush=True)
    else:
        print(f"[Monitor] Archivo YARA no encontrado: {YARA_RULES_FILE}", flush=True)
        rules = None
        YARA_OK = False
except ImportError:
    print("[Monitor] yara-python no disponible — análisis YARA desactivado", flush=True)
    rules = None
    YARA_OK = False
except Exception as e:
    print(f"[Monitor] Error compilando YARA: {e}", flush=True)
    rules = None
    YARA_OK = False


# -------------------------------------------------------
# Telegram
# -------------------------------------------------------
def enviar_telegram(mensaje: str):
    try:
        r = _feed_session.post(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": mensaje},
            timeout=10,
        )
        if r.status_code != 200:
            print(f"[Telegram] HTTP {r.status_code}", flush=True)
    except Exception as e:
        print(f"[Telegram] Error: {e}", flush=True)


# -------------------------------------------------------
# Descarga de URL phishing
# -------------------------------------------------------
def descargar_url(url: str) -> bytes | None:
    try:
        r = _analysis_session.get(url, timeout=DOWNLOAD_TO, stream=False)
        if r.status_code == 200:
            return r.content
    except Exception:
        pass
    return None


# -------------------------------------------------------
# Feeds
# -------------------------------------------------------
def request_feed(url: str, retries: int = 3, timeout: int = 20) -> str | None:
    for i in range(retries):
        try:
            r = _feed_session.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.text
        except Exception as e:
            print(f"[Feed] Error {url} (intento {i + 1}): {e}", flush=True)
        if i < retries - 1:
            time.sleep(3 * (i + 1))
    return None


def obtener_openphish() -> list[str]:
    texto = request_feed(OPENPHISH_FEED)
    if not texto:
        return []
    return [l.strip() for l in texto.splitlines() if l.strip().startswith("http")]


def obtener_phishtank(limit: int = 100) -> list[str]:
    texto = request_feed(PHISHTANK_FEED, timeout=30)
    if not texto:
        return []
    urls = []
    for line in texto.splitlines()[1:]:
        partes = line.split(",")
        if len(partes) >= 2:
            url = partes[1].strip().strip('"')
            if url.startswith("http"):
                urls.append(url)
                if len(urls) >= limit:
                    break
    return urls


# -------------------------------------------------------
# Análisis
# -------------------------------------------------------
def analizar_url(url: str, fuente: str, conn: sqlite3.Connection):
    marcar_procesada(conn, url)

    if not YARA_OK or rules is None:
        return

    contenido = descargar_url(url)
    if not contenido:
        return

    try:
        matches = rules.match(data=contenido)
    except Exception as e:
        print(f"[YARA] Error en {url}: {e}", flush=True)
        return

    if not matches:
        return

    reglas = ", ".join(str(m) for m in matches)
    ts = hora_colombia()
    mensaje = (
        f"⚠️ PHISHING KIT DETECTADO\n\n"
        f"URL: {url}\n"
        f"Fuente: {fuente}\n"
        f"Regla YARA: {reglas}\n"
        f"Fecha: {ts} (COT)"
    )

    enviar_telegram(mensaje)
    print(f"✅ ALERTA → {url} [{reglas}]", flush=True)

    try:
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{ts} | {fuente} | URL: {url} | Regla: {reglas}\n")
    except Exception:
        pass


def _task(args):
    url, fuente, conn = args
    try:
        analizar_url(url, fuente, conn)
    except Exception as e:
        print(f"[Worker] Excepción: {e}", flush=True)


# -------------------------------------------------------
# Función principal
# -------------------------------------------------------
def run_monitor():
    conn = init_db()
    total = total_procesadas(conn)

    print("🔍 Monitor de phishing activo.", flush=True)
    print(f"📡 Fuentes: OpenPhish + PhishTank | Workers: {NUM_WORKERS}", flush=True)
    print(f"📂 URLs ya procesadas (DB): {total}", flush=True)
    print(f"🧬 YARA: {'activo ✓' if YARA_OK else 'desactivado'}", flush=True)
    print(
        f"⚡ SSL verify: OFF | Timeout: {DOWNLOAD_TO}s | Ciclo: {CYCLE_SLEEP}s",
        flush=True,
    )

    executor = ThreadPoolExecutor(max_workers=NUM_WORKERS, thread_name_prefix="monitor")

    ciclo = 0
    error_delay = CYCLE_SLEEP

    while True:
        try:
            feed_futures = {
                executor.submit(obtener_openphish): "OpenPhish",
                executor.submit(obtener_phishtank): "PhishTank",
            }

            urls_por_fuente: list[tuple[str, str]] = []
            for fut in as_completed(feed_futures):
                fuente = feed_futures[fut]
                try:
                    for url in fut.result():
                        if not url_procesada(conn, url):
                            urls_por_fuente.append((url, fuente))
                except Exception as e:
                    print(f"[Feed:{fuente}] Error: {e}", flush=True)

            nuevas = len(urls_por_fuente)
            ciclo += 1
            total_db = total_procesadas(conn)
            print(
                f"[Monitor] Ciclo {ciclo} — {nuevas} URLs nuevas | total_db={total_db}",
                flush=True,
            )

            if ciclo % CLEANUP_EVERY == 0:
                limpiar_db(conn)

            if urls_por_fuente:
                tareas = [(url, fuente, conn) for url, fuente in urls_por_fuente]
                list(executor.map(_task, tareas, timeout=CYCLE_SLEEP * 2))

            error_delay = CYCLE_SLEEP

        except Exception as e:
            print(f"[Monitor] Error en ciclo principal: {e}", flush=True)
            error_delay = min(error_delay * 2, 300)

        time.sleep(error_delay)


if __name__ == "__main__":
    run_monitor()
