<?php
// ============================================================
// api/soru-cozme.php — Vercel (serverless) uyumlu sürüm
// Oturum: imzalı + şifreli ÇEREZ (session_start() yok)
// ============================================================

// ---------- 1) AYARLAR ----------
$api_key = getenv('NVIDIA_API_KEY') ?: '';
$model   = 'nvidia/nemotron-3.5-bolt-e4b';
$api_url = 'https://integrate.api.nvidia.com/v1/chat/completions';

$sayfa_baslik = 'Lise 1 Matematik — Demo Soru Çözme Scripti';
$alt_baslik   = 'Butona bas, sorular hazırlansın, çöz ve sonucunu gör.';
$buton_yazi   = 'Soruları Hazırla';

$soru_sayisi  = 10;
$sik_sayisi   = 5;

$ders_komutu = 'Lise 1 matematik dersi {SORU_SAYISI} soru hazırla.';
$ek_talimat  = 'Sorular 9. sınıf (Lise 1) müfredatına uygun olsun: kümeler, sayılar, denklemler ve eşitsizlikler, '
             . 'üslü ve köklü sayılar, oran-orantı, bölünebilme, mantık, fonksiyonlara giriş gibi konulardan dengeli dağılsın. '
             . 'Zorluk kolaydan orta seviyeye doğru ilerlesin. Sorular birbirinin tekrarı olmasın.';

$max_uretim_saat = 10;

// Çerez adı ve ömrü
define('COOKIE_NAME', 'qstate');
define('COOKIE_TTL', 3600); // 1 saat

// ============================================================
// 2) ÇEREZ TABANLI OTURUM (AES-256-GCM + HMAC)
// ============================================================

function b64u_enc(string $s): string {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}
function b64u_dec(string $s): string {
    $pad = strlen($s) % 4;
    if ($pad) $s .= str_repeat('=', 4 - $pad);
    return base64_decode(strtr($s, '-_', '+/')) ?: '';
}

/**
 * Cookie'deki durumu şifreli+imzalı olarak okur.
 * Format: b64u(nonce|tag|chipher) . '.' . b64u(hmac)
 */
function state_read(): array {
    $raw = $_COOKIE[COOKIE_NAME] ?? '';
    if ($raw === '' || !str_contains($raw, '.')) return [];

    [$encPart, $macPart] = explode('.', $raw, 2);
    $secret = getenv('APP_SECRET') ?: 'change-me-please';
    $expected = b64u_enc(hash_hmac('sha256', $encPart, $secret, true));
    if (!hash_equals($expected, $macPart)) return [];

    $blob = b64u_dec($encPart);
    if (strlen($blob) < 28) return [];

    $nonce = substr($blob, 0, 12);
    $tag   = substr($blob, 12, 16);
    $cipher= substr($blob, 28);

    $key = hash('sha256', $secret, true); // 32 byte
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($plain === false) return [];

    $data = json_decode($plain, true);
    if (!is_array($data)) return [];
    if (($data['exp'] ?? 0) < time()) return [];
    return $data;
}

function state_write(array $data): void {
    $data['exp'] = time() + COOKIE_TTL;
    $plain = json_encode($data, JSON_UNESCAPED_UNICODE);

    $secret = getenv('APP_SECRET') ?: 'change-me-please';
    $key = hash('sha256', $secret, true);
    $nonce = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);

    $blob = $nonce . $tag . $cipher;
    $encPart = b64u_enc($blob);
    $macPart = b64u_enc(hash_hmac('sha256', $encPart, $secret, true));
    $cookie  = $encPart . '.' . $macPart;

    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
              || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

    setcookie(COOKIE_NAME, $cookie, [
        'expires'  => time() + COOKIE_TTL,
        'path'     => '/',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE[COOKIE_NAME] = $cookie;
}

function state_clear(): void {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
              || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    setcookie(COOKIE_NAME, '', [
        'expires' => time() - 3600, 'path' => '/', 'secure' => $secure,
        'httponly' => true, 'samesite' => 'Lax',
    ]);
    unset($_COOKIE[COOKIE_NAME]);
}

// ============================================================
// 3) API YARDIMCILARI
// ============================================================

function json_out(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function nv_chat(string $url, string $key, array $payload): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $key, 'Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT        => 240,
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, (string)$body, $err];
}

// ============================================================
// 4) İSTEK İŞLEME
// ============================================================

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action'])) {
    @set_time_limit(280);
    $action = $_GET['action'];
    $state  = state_read();

    // ---- Soruları üret ----
    if ($action === 'generate') {
        if ($api_key === '') {
            json_out(['error' => 'NVIDIA API anahtarı ayarlanmamış (Vercel ortam değişkeni: NVIDIA_API_KEY).'], 500);
        }

        $now = time();
        $times = array_values(array_filter($state['gen_times'] ?? [], fn($t) => $t > $now - 3600));
        if (count($times) >= $max_uretim_saat) {
            json_out(['error' => 'Saatlik soru üretme sınırına ulaştın.'], 429);
        }
        $times[] = $now;

        $komut = str_replace('{SORU_SAYISI}', (string)$soru_sayisi, $ders_komutu);

        $sys = "Sen deneyimli bir öğretmensin. Kullanıcının istediği konuda tam {$soru_sayisi} adet çoktan seçmeli soru hazırla. "
             . "Her soruda tam {$sik_sayisi} şık olsun ve yalnızca biri doğru olsun. Doğru şıkkın yeri sorulara rastgele dağılsın. "
             . "Şıklara A), B) gibi harf ekleme; sadece şık metnini yaz. "
             . "Yazıda LaTeX, ters eğik çizgi (\\) ve markdown kullanma; matematik için düz metin ve Unicode karakterleri (x², √, ≤, ≥, ½, π) kullan. "
             . "Açıklama (explanation) en fazla 1-2 kısa cümle olsun. Türkçe yaz. "
             . ($ek_talimat !== '' ? "Ek talimat: {$ek_talimat} " : '')
             . "Yanıtı SADECE geçerli JSON olarak ver, başka hiçbir şey yazma: "
             . "{\"questions\":[{\"q\":\"soru metni\",\"options\":[\"şık1\",\"şık2\",...],\"answer\":0,\"explanation\":\"kısa çözüm\"}]} "
             . "(answer = doğru şıkkın 0 tabanlı sırası).";

        $valid = [];
        $last_err = 'Model geçerli soru üretemedi.';
        for ($try = 0; $try < 2 && count($valid) < $soru_sayisi; $try++) {
            [$code, $body, $err] = nv_chat($api_url, $api_key, [
                'model' => $model,
                'messages' => [['role' => 'system', 'content' => $sys], ['role' => 'user', 'content' => $komut]],
                'temperature' => 0.7, 'top_p' => 0.95, 'max_tokens' => 7000, 'stream' => false,
                'chat_template_kwargs' => ['enable_thinking' => false],
            ]);
            if ($err) { $last_err = 'cURL hatası: ' . $err; continue; }
            if ($code >= 400) { $last_err = "NVIDIA API HTTP $code: " . mb_substr($body, 0, 300); continue; }

            $resp = json_decode($body, true);
            $content = $resp['choices'][0]['message']['content'] ?? '';
            if (!preg_match('/\{.*\}/s', $content, $m)) continue;
            $data = json_decode($m[0], true);
            $qs = is_array($data['questions'] ?? null) ? $data['questions'] : [];

            $valid = [];
            foreach ($qs as $q) {
                $text = trim((string)($q['q'] ?? ''));
                $opts = is_array($q['options'] ?? null) ? array_values(array_map(fn($o) => trim((string)$o), $q['options'])) : [];
                $ans  = $q['answer'] ?? null;
                if ($text === '' || count($opts) !== $sik_sayisi || !is_int($ans) || $ans < 0 || $ans >= $sik_sayisi) continue;
                $valid[] = ['q' => $text, 'options' => $opts, 'answer' => $ans, 'explanation' => trim((string)($q['explanation'] ?? ''))];
            }
        }
        if (count($valid) < $soru_sayisi) {
            json_out(['error' => $last_err . ' (' . count($valid) . '/' . $soru_sayisi . ' geçerli soru) — tekrar dene.'], 502);
        }
        $valid = array_slice($valid, 0, $soru_sayisi);

        // Cevap anahtarını çereze şifreli olarak yaz
        $state['key'] = array_map(
            fn($v) => ['answer' => $v['answer'], 'explanation' => $v['explanation']],
            $valid
        );
        $state['gen_times'] = $times;
        state_write($state);

        $public = array_map(fn($v) => ['q' => $v['q'], 'options' => $v['options']], $valid);
        json_out(['questions' => $public]);
    }

    // ---- Sonuç için cevap anahtarını ver ----
    if ($action === 'key') {
        if (empty($state['key'])) {
            json_out(['error' => 'Oturum süresi dolmuş. Soruları yeniden hazırla.'], 400);
        }
        json_out(['key' => $state['key']]);
    }

    json_out(['error' => 'Bilinmeyen işlem.'], 400);
}

$harfler = array_slice(['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'], 0, $sik_sayisi);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($sayfa_baslik) ?></title>
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f4f6fb; color: #1f2937; padding: 20px; display: flex; justify-content: center; }
    .wrap { width: 100%; max-width: 820px; }
    h1 { font-size: 24px; color: #111827; margin-bottom: 4px; }
    .sub { color: #6b7280; font-size: 14px; margin-bottom: 18px; }
    button { padding: 12px 22px; border: none; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; color: #fff; background: #2563eb; }
    button:hover { background: #1d4ed8; }
    button:disabled { background: #cbd5e1; color: #94a3b8; cursor: not-allowed; }
    button.green { background: #16a34a; } button.green:hover { background: #15803d; }
    #status { margin: 12px 0; font-size: 14px; color: #475569; min-height: 20px; }
    #status.err { color: #b91c1c; white-space: pre-wrap; }
    .bar { position: sticky; top: 0; z-index: 5; background: #f4f6fb; padding: 10px 0; display: none; align-items: center; gap: 12px; flex-wrap: wrap; border-bottom: 1px solid #e5e7eb; margin-bottom: 14px; }
    .progress { flex: 1; min-width: 160px; font-size: 14px; color: #374151; }
    .progress .track { height: 8px; background: #e5e7eb; border-radius: 99px; margin-top: 6px; overflow: hidden; }
    .progress .fill { height: 100%; width: 0; background: #2563eb; transition: width .2s; }
    .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 14px; padding: 16px; margin-bottom: 14px; }
    .card .no { font-size: 12px; font-weight: 700; color: #2563eb; margin-bottom: 6px; }
    .card .q { font-size: 16px; line-height: 1.5; margin-bottom: 10px; white-space: pre-wrap; }
    .opt { display: flex; gap: 10px; align-items: flex-start; padding: 9px 12px; border: 1px solid #e5e7eb; border-radius: 10px; margin-bottom: 7px; cursor: pointer; font-size: 15px; }
    .opt:hover { background: #f8fafc; }
    .opt input { margin-top: 4px; }
    .opt b { min-width: 18px; color: #475569; }
    .opt.selected { border-color: #2563eb; background: #eff6ff; }
    .opt.correct { border-color: #16a34a; background: #dcfce7; }
    .opt.wrong { border-color: #dc2626; background: #fee2e2; }
    .exp { display: none; margin-top: 8px; font-size: 14px; color: #374151; background: #f8fafc; border-left: 3px solid #94a3b8; padding: 8px 10px; border-radius: 6px; }
    .badge { display: inline-block; font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 99px; margin-left: 8px; }
    .badge.ok { background: #dcfce7; color: #166534; } .badge.no { background: #fee2e2; color: #991b1b; } .badge.empty { background: #e5e7eb; color: #475569; }
    #summary { display: none; background: #111827; color: #fff; border-radius: 14px; padding: 18px; margin-bottom: 16px; }
    #summary h2 { font-size: 20px; margin-bottom: 10px; }
    #summary .stats { display: flex; gap: 18px; flex-wrap: wrap; font-size: 15px; }
    #summary .score { font-size: 34px; font-weight: 800; }
</style>
</head>
<body>
<div class="wrap">
    <h1><?= htmlspecialchars($sayfa_baslik) ?></h1>
    <div class="sub"><?= htmlspecialchars($alt_baslik) ?></div>

    <button id="gen-btn"><?= htmlspecialchars($buton_yazi) ?></button>
    <div id="status"></div>

    <div class="bar" id="bar">
        <div class="progress">
            <span id="prog-text">Cevaplanan: 0 / 0</span>
            <div class="track"><div class="fill" id="prog-fill"></div></div>
        </div>
        <button class="green" id="result-btn">Sonucu Göster</button>
    </div>

    <div id="summary"></div>
    <div id="quiz"></div>
</div>

<script>
(function () {
    const LETTERS = <?= json_encode($harfler) ?>;
    const $ = id => document.getElementById(id);
    let questions = [];
    let answers = [];
    let finished = false;

    function setStatus(msg, err) { const s = $('status'); s.textContent = msg; s.className = err ? 'err' : ''; }

    function updateProgress() {
        const done = answers.filter(a => a !== null).length;
        $('prog-text').textContent = 'Cevaplanan: ' + done + ' / ' + questions.length;
        $('prog-fill').style.width = (questions.length ? done / questions.length * 100 : 0) + '%';
    }

    function render() {
        const quiz = $('quiz');
        quiz.innerHTML = '';
        questions.forEach((q, i) => {
            const card = document.createElement('div');
            card.className = 'card';
            card.id = 'card' + i;

            const no = document.createElement('div'); no.className = 'no'; no.textContent = 'SORU ' + (i + 1);
            const qt = document.createElement('div'); qt.className = 'q'; qt.textContent = q.q;
            card.appendChild(no); card.appendChild(qt);

            q.options.forEach((opt, k) => {
                const lab = document.createElement('label'); lab.className = 'opt'; lab.id = 'opt' + i + '_' + k;
                const inp = document.createElement('input'); inp.type = 'radio'; inp.name = 'q' + i; inp.value = k;
                inp.addEventListener('change', () => {
                    if (finished) return;
                    answers[i] = k;
                    q.options.forEach((_, j) => $('opt' + i + '_' + j).classList.toggle('selected', j === k));
                    updateProgress();
                });
                const b = document.createElement('b'); b.textContent = LETTERS[k] + ')';
                const t = document.createElement('span'); t.textContent = opt;
                lab.appendChild(inp); lab.appendChild(b); lab.appendChild(t);
                card.appendChild(lab);
            });

            const exp = document.createElement('div'); exp.className = 'exp'; exp.id = 'exp' + i;
            card.appendChild(exp);
            quiz.appendChild(card);
        });
        $('bar').style.display = 'flex';
        updateProgress();
    }

    $('gen-btn').addEventListener('click', async () => {
        $('gen-btn').disabled = true;
        $('summary').style.display = 'none';
        $('bar').style.display = 'none';
        $('quiz').innerHTML = '';
        finished = false;
        setStatus('Sorular hazırlanıyor… (30-90 saniye sürebilir)');
        try {
            const res = await fetch('?action=generate', { method: 'POST' });
            const data = await res.json().catch(() => ({ error: 'Sunucu JSON döndürmedi (HTTP ' + res.status + ')' }));
            if (!res.ok || data.error) throw new Error(data.error);
            questions = data.questions;
            answers = questions.map(() => null);
            render();
            setStatus('✅ ' + questions.length + ' soru hazır. İstediğin zaman "Sonucu Göster"e basabilirsin.');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (e) { setStatus('⚠ ' + e.message, true); }
        finally { $('gen-btn').disabled = false; }
    });

    $('result-btn').addEventListener('click', async () => {
        if (!questions.length || finished) return;
        const empty = answers.filter(a => a === null).length;
        if (empty > 0 && !confirm(empty + ' soru boş. Yine de sonucu göstermek istiyor musun?')) return;

        $('result-btn').disabled = true;
        try {
            const res = await fetch('?action=key', { method: 'POST' });
            const data = await res.json().catch(() => ({ error: 'Sunucu JSON döndürmedi.' }));
            if (!res.ok || data.error) throw new Error(data.error);
            showResults(data.key);
        } catch (e) { setStatus('⚠ ' + e.message, true); $('result-btn').disabled = false; }
    });

    function showResults(key) {
        finished = true;
        let correct = 0, wrong = 0, blank = 0;

        questions.forEach((q, i) => {
            const right = key[i].answer;
            const given = answers[i];
            const card = $('card' + i);
            const badge = document.createElement('span');
            badge.className = 'badge';

            if (given === null) { blank++; badge.classList.add('empty'); badge.textContent = 'Boş'; }
            else if (given === right) { correct++; badge.classList.add('ok'); badge.textContent = 'Doğru'; }
            else { wrong++; badge.classList.add('no'); badge.textContent = 'Yanlış'; }
            card.querySelector('.no').appendChild(badge);

            q.options.forEach((_, k) => {
                const el = $('opt' + i + '_' + k);
                el.classList.remove('selected');
                el.querySelector('input').disabled = true;
                if (k === right) el.classList.add('correct');
                else if (k === given) el.classList.add('wrong');
            });

            const exp = $('exp' + i);
            exp.textContent = key[i].explanation
                ? 'Doğru cevap: ' + LETTERS[right] + ') — ' + key[i].explanation
                : 'Doğru cevap: ' + LETTERS[right] + ')';
            exp.style.display = 'block';
        });

        const total = questions.length;
        const pct = Math.round(correct / total * 100);
        const s = $('summary');
        s.innerHTML = '';
        const h = document.createElement('h2'); h.textContent = 'Sonuçların';
        const stats = document.createElement('div'); stats.className = 'stats';
        const sc = document.createElement('div'); sc.innerHTML = '<div class="score"></div><div>başarı</div>';
        sc.querySelector('.score').textContent = '%' + pct;
        stats.appendChild(sc);
        [['✅ Doğru', correct], ['❌ Yanlış', wrong], ['⬜ Boş', blank], ['📋 Toplam', total]].forEach(([label, val]) => {
            const d = document.createElement('div'); d.textContent = label + ': ' + val; stats.appendChild(d);
        });
        s.appendChild(h); s.appendChild(stats);
        s.style.display = 'block';
        window.scrollTo({ top: 0, behavior: 'smooth' });
        setStatus('Sonuçlar gösterildi. Yeni sorular için "<?= htmlspecialchars($buton_yazi, ENT_QUOTES) ?>" butonuna bas.');
    }
})();
</script>
</body>
</html>
