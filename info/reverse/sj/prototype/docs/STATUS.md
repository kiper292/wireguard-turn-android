# SJ WebSocket Proxy — Статус разработки

**Дата:** 11 апреля 2026 г.

## Цель
Создать двусторонний туннель для передачи данных через WebRTC VP9 видеопоток поверх WebSocket сигнализации SaluteJazz (LiveKit-based SFU).

## Что работает ✅

### Базовая инфраструктура
| Компонент | Статус | Описание |
|-----------|--------|----------|
| WebSocket подключение к SFU | ✅ | Подключение к `wss://ws.salutejazz.ru/connector` |
| HTTP API вызовы | ✅ | `create-meeting`, `preconnect`, `public-info`, `user/info` |
| Join / Join-response | ✅ | Присоединение к комнате, получение session/group ID |
| Initial SDP offer/answer (subscriber) | ✅ | DataChannel-only subscriber PC |
| ICE соединение (subscriber) | ✅ | ICE connected state достигается |
| Публикация AUDIO трека | ✅ | `rtc:track:add` → `rtc:track:published` |
| Публикация VIDEO трека (VP9, simulcast) | ✅ | С layers HIGH/MEDIUM/LOW |
| Publisher SDP offer/answer | ✅ | Audio + Video + DataChannel |
| Ping/Pong keepalive | ✅ | Каждые 5 секунд |
| Тайминги сообщений | ✅ | 1.5s между AUDIO/VIDEO, 200ms subscription delay |
| JSON формат сообщений | ✅ | Точно совпадает с HAR (key order, spacing) |
| SDP publisher offer | ✅ | **Байт-в-байт** идентичен HAR (1152 bytes, 38 lines) |

### SDP эмуляция (sdp_emulate.go)
- ✅ Точные кодеки: `111 63 9 0 8 13 110 126` (opus, red, G722, PCMU, PCMA, CN, telephone-event)
- ✅ RED fmtp: `a=fmtp:63 111/111`
- ✅ Extmap порядок: 1-2-3-4 (ssrc-audio-level, abs-send-time, transport-wide-cc, sdes:mid)
- ✅ Direction: `a=sendonly` (не sendrecv)
- ✅ MSID format: `a=msid:- <uuid>` (не `audio audio`)
- ✅ MSID semantic: `a=msid-semantic:  WMS` (с двумя пробелами)
- ✅ Line endings: `\n` (LF, не CRLF)
- ✅ ICE credentials: ufrag=4 символа, pwd=24 символа
- ✅ Cname: 16-char random string (не "audio")
- ✅ `a=ice-options:trickle`
- ✅ `a=rtcp:9 IN IP4 0.0.0.0`
- ✅ **Итог: 1152 bytes = 1152 bytes, все строки совпадают по длине**

### Автоматическая подписка на треки
- ✅ SDP parser (`parseTrackSIDsFromSDP`) — извлечение SID из renegotiation offer
- ✅ Renegotiation handler — парсинг SDP и auto-subscribe для server и client
- ✅ ICE connection state logging для publisher PC

## Что НЕ работает ❌

### Критическая проблема
**SFU не включает треки в `participants:update` для Go клиента**

```
HAR сервер получает:  VVpAYGC4:tracks=1 [sid=TR_AMdnYjqTJjpkE5, type=AUDIO]
Наш Go сервер получает: zqfYTiuX:tracks=0  ← ПУСТО!
```

Это означает:
- SFU не шлёт renegotiation offers с медиа-треками
- `OnTrack` callback никогда не срабатывает
- Данные через VP9 не передаются
- Bidirectional туннель не работает

### Что НЕ помогло (попробовали всё):

| # | Попытка | Результат |
|---|---------|-----------|
| 1 | `auto_subscribe=1` / `auto_subscribe=true` в WebSocket URL | ❌ |
| 2 | Убрали Sec-Ch-Ua, Sec-Fetch-* заголовки | ❌ |
| 3 | Добавили recvonly transceivers (audio + video) | ❌ |
| 4 | Убрали datachannel из publisher PC | ❌ |
| 5 | Добавили кодеки RED/CN/telephone-event | ❌ |
| 6 | Добавили extmap headers (1-2-3-4) | ❌ |
| 7 | Publisher ICE connection state logging | ❌ |
| 8 | Точный порядок кодеков как в HAR | ❌ |
| 9 | HAR-exact JSON формат (key order, spacing) | ❌ |
| 10 | **Байт-идентичный publisher offer SDP** (1152 bytes) | ❌ |
| 11 | `a=sendonly` вместо `a=sendrecv` | ❌ |
| 12 | `a=msid:- <uuid>` вместо `a=msid:audio audio` | ❌ |
| 13 | Короткие ICE credentials (ufrag=4, pwd=24) | ❌ |
| 14 | Random 16-char cname вместо "audio" | ❌ |

## Корневая причина

SFU SaluteJazz определяет Go/pion клиента **на уровне WebRTC/DTLS стека**, не на уровне сигнализации:

1. **DTLS fingerprint** — pion генерирует уникальный fingerprint, отличающийся от Chrome
2. **ICE behavior** — паттерны candidate gathering отличаются
3. **WebRTC stack internals** — LiveKit может определя тип клиента по внутреннему поведению

Все наши попытки на уровне **сигнализации** (WebSocket сообщения, SDP, JSON формат) не повлияли на это.

## Возможные решения

### Вариант A: libgowebrtc (рекомендуется)
- Pion-compatible wrapper для **нативного libwebrtc**
- GitHub: https://github.com/thesyncim/libgowebrtc
- ✅ DTLS fingerprint = Chrome (нативный libwebrtc)
- ✅ Pion-compatible API — минимум изменений
- ✅ Готовые Windows бинарники (не надо собирать)
- ✅ Активно поддерживается (март 2026)
- ⚠️ Только Windows/Darwin (Linux нужна сборка)
- ⏱ Оценка: 1-2 дня

### Вариант B: Headless Chrome через CDP
- Запуск реального Chrome для подключения к SFU
- ✅ 100% Chrome DTLS fingerprint
- ⚠️ Нужно управлять Chrome процессом
- ⚠️ Извлечение SID треков через JavaScript injection
- ⏱ Оценка: 1-2 дня

### Вариант C: DataChannel вместо VP9
- Использовать существующий `m=application` DataChannel
- ✅ Уже работает (subscriber PC имеет datachannel)
- ⚠️ Не VP9 туннель — другой подход к передаче данных
- ⚠️ Нужно проверить работает ли DC между двумя pion клиентами

### Вариант D: C++ libwebrtc с нуля
- Полная переписывание на C++ с нативным libwebrtc
- ✅ Полный контроль
- ❌ Очень высокая сложность (недели работы)
- ❌ Потеря всего Go кода

## Структура проекта

```
wg-ws-proxy/
├── server/
│   ├── main.go           # Основной серверный код (~1200 строк)
│   ├── sdp_emulate.go    # SDP эмуляция HAR формата (~340 строк)
│   └── wg-proxy-server.exe
├── client/
│   ├── main.go           # Основной клиентский код (~970 строк)
│   └── wg-proxy-client.exe
└── conn_info.json        # Общие параметры подключения

docs/
└── HAR_DEEP_ANALYSIS.md  # Детальный анализ HAR файлов
```

## Git история
```
6d627a3 feat: byte-identical publisher offer SDP (1152 bytes match HAR)
09a0fcb experiment: HAR-exact JSON format (key order, spacing)
2522218 refactor: exact HAR codec order, RED fmtp, extmap ordering
...
```

## Следующий шаг
Выбрать один из вариантов A-D для продолжения разработки.
**Рекомендация:** Вариант A (libgowebrtc) — лучший баланс сложности и вероятности успеха.
