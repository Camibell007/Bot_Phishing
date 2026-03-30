/* regla.yara */

rule regla
{
    meta:
        description = "Detecta kits de phishing que exfiltran credenciales a Telegram con fingerprinting de IP"
        author = "Analyst"
        date = "2026-03-11"
        category = "phishing"
        version = "2.0"

    strings:

        /* ------------------------------
           Capa 1: Infraestructura Telegram
           ------------------------------ */
        $tg_api    = "api.telegram.org/bot" nocase
        $tg_send   = "/sendMessage"         nocase
        $tg_doc    = "/sendDocument"        nocase
        $tg_var1   = "telegram_bot_id"      nocase
        $tg_var2   = "chat_id"              nocase

        /* ------------------------------
           Capa 1b: Otros canales de exfiltración
           ------------------------------ */
        $discord   = "discord.com/api/webhooks"  nocase
        $discord2  = "discordapp.com/api"         nocase
        $slack_wh  = "hooks.slack.com/services"   nocase

        /* ------------------------------
           Capa 2: Exfiltración / Comportamiento
           ------------------------------ */
        $ajax      = "$.ajax("         nocase
        $xhr       = "XMLHttpRequest"  nocase
        $fetch_fn  = "fetch("          nocase
        $formdata  = "FormData("       nocase
        $json      = "JSON.stringify"  nocase

        /* ------------------------------
           Capa 2b: Ofuscación común
           ------------------------------ */
        $b64_decode = "atob("           nocase
        $eval_enc   = /eval\s*\(.*atob/
        $str_split  = /["'][a-z]+["']\s*\+\s*["'][a-z]+["']/
        $hex_enc    = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/

        /* ------------------------------
           Capa 3: Recolección de IP / Fingerprint
           ------------------------------ */
        $ip1  = "api.ipify.org"         nocase
        $ip2  = "ipinfo.io"             nocase
        $ip3  = "ip-api.com"            nocase
        $ip4  = "ipapi.co"              nocase
        $ip5  = "ipgeolocation.io"      nocase
        $ip6  = "freegeoip"             nocase
        $ip7  = "geolocation-db.com"    nocase
        $ip8  = "geoiplookup"           nocase
        $ip9  = "checkip.amazonaws.com" nocase
        $ip10 = "myexternalip.com"      nocase

        /* ------------------------------
           Capa 4: Recolección de credenciales
           ------------------------------ */
        $pass1  = "password"    nocase
        $pass2  = "passwd"      nocase
        $email1 = "email"       nocase
        $cred1  = "credentials" nocase
        $card1  = "cardnumber"  nocase
        $card2  = "cvv"         nocase

    condition:

        /* Infraestructura: Telegram O canal alternativo */
        (
            (1 of ($tg_api,$tg_send,$tg_doc) and 1 of ($tg_var1,$tg_var2))
            or 1 of ($discord,$discord2,$slack_wh)
        )
        and

        /* Exfiltración: método HTTP O indicio de ofuscación */
        (1 of ($ajax,$xhr,$fetch_fn,$formdata,$json) or 1 of ($b64_decode,$eval_enc,$str_split,$hex_enc))
        and

        /* Fingerprinting o recolección de credenciales */
        (1 of ($ip1,$ip2,$ip3,$ip4,$ip5,$ip6,$ip7,$ip8,$ip9,$ip10) or 2 of ($pass1,$pass2,$email1,$cred1,$card1,$card2))
}
