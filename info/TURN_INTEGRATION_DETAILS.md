# Интеграция VK TURN Proxy (Архитектура)

В данном документе описана архитектура интеграции VK TURN Proxy в форк клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android).

## Содержание

1. [Нативный уровень (Go / JNI)](#1-нативный-уровень-go--jni)
2. [Слой конфигурации (Java)](#2-слой-конфигурации-java)
3. [Логика управления и UI (Kotlin)](#3-логика-управления-и-ui-kotlin)
4. [Протокол взаимодействия](#4-протокол-взаимодействия)
5. [Формат метаданных в конфигурации](#5-формат-метаданных-в-конфигурации)
6. [Расширенные настройки TURN](#6-расширенные-настройки-turn)
7. [Хранение настроек](#7-хранение-настроек)
8. [Архитектура запуска TURN](#8-архитектура-запуска-turn)
9. [PhysicalNetworkMonitor](#9-physicalnetworkmonitor)
10. [Режимы получения credentials](#10-режимы-получения-credentials)
11. [VK Auth Flow](#11-vk-auth-flow)
12. [Метрики и диагностика](#12-метрики-и-диагностика)
13. [DNS Resolver](#13-dns-resolver)
14. [Per-Stream Кэширование Credentials](#14-per-stream-кэширование-credentials)
15. [UI структура карточки TURN](#15-ui-структура-карточки-turn)
16. [VK Captcha с WebView Fallback](#16-vk-captcha-с-webview-fallback)

---

## 1. Нативный уровень (Go / JNI)

### `tunnel/tools/libwg-go/jni.c`

- **`wgProtectSocket(int fd)`**: Функция для вызова `VpnService.protect(fd)` через JNI. Позволяет TURN-клиенту выводить трафик за пределы VPN-туннеля.
  - Валидация fd (возвращает -1 при невалидном fd)
  - Логирование результата (SUCCESS/FAILED)
  - **bindSocket()** — привязка сокета к кэшированному Network object для маршрутизации через правильный интерфейс (вызывается только если `current_network_global != NULL`)

- **`wgTurnProxyStart/Stop`**: Экспортированные методы для управления жизненным циклом прокси-сервера.
  - Принимает `networkHandle` (long long) для привязки к конкретному Network
  - Вызывает `update_current_network()` для кэширования Network object перед запуском
  - Параметры: `peerAddr`, `vklink`, `mode`, `n` (streams), `udp`, `listenAddr`, `turnIp`, `turnPort`, `peerType`, `streamsPerCred`, `watchdogTimeout`, `networkHandle`

- **`wgNotifyNetworkChange()`**: Функция для сброса DNS resolver и HTTP-соединений при переключении сети (WiFi <-> 4G). Обеспечивает быстрое восстановление соединения после смены сетевого интерфейса.

- **`update_current_network()`**: Внутренняя функция для кэширования Network object и NetworkHandle. Используется для `bindSocket()` при защите сокетов. Вызывается из `wgTurnProxyStart()` и сбрасывается в `wgTurnProxyStop()`.

- **Стабилизация ABI**: Использование простых C-типов (`const char *`, `int`, `long long`) для передачи параметров прокси, что устраняет ошибки выравнивания памяти в Go-структурах на разных архитектурах. Параметры `udp` и `streamsPerCred` имеют тип `int` для корректной работы JNI.

- **Детальное логирование**: `wgProtectSocket()` логирует валидацию fd, вызов protect() и результат (SUCCESS/FAILED), а также результат bindSocket() с указанием network handle.

### `tunnel/tools/libwg-go/turn-client.go`

- **Peer Type**: Три режима работы, управляемые параметром `peerType`:
  - `"proxy_v2"` — DTLS с передачей Session ID + Stream ID handshake (17 байт)
  - `"proxy_v1"` — DTLS без Session ID + Stream ID handshake (аналог v2, но сервер не агрегирует потоки)
  - `"wireguard"` — без DTLS, прямой relay (аналог legacy `noDtls=true`)
  - Функция `runDTLS(ctx, relayConn, peer, okchan, sendHandshake bool)` принимает флаг `sendHandshake`; при `false` блок session_id+stream_id пропускается

- **Session ID Handshake (Multi-Stream Support)**: Клиент генерирует уникальный 16-байтный UUID при каждом запуске туннеля и отправляет его первым пакетом после DTLS рукопожатия в каждом потоке (только для Proxy v2). Это позволяет серверу агрегировать несколько DTLS-сессий в одно стабильное UDP-соединение до WireGuard сервера, решая проблему "Endpoint Thrashing".
  - Session ID (16 байт) + Stream ID (1 байт) = 17 байт handshake
  - Отправка происходит после успешного DTLS handshake
  - **Proxy v1** пропускает этот handshake

- **Round-Robin Load Balancing**: Реализация Hub-сервера, который поддерживает `n` параллельных DTLS-соединений. Вместо использования одного «липкого» потока, клиент равномерно распределяет исходящие пакеты WireGuard между всеми готовыми (ready) DTLS-соединениями. Это повышает общую пропускную способность и устойчивость к потерям в отдельных потоках.
  - Переменная `lastUsed` циклически переключается между потоками
  - Пакеты направляются в первый доступный ready-поток

- **Streams Per Credentials**: Настраиваемый параметр `streamsPerCred` (по умолчанию 4) определяет, сколько потоков разделяют один кэш credentials. Кэш-ID вычисляется как `streamID / streamsPerCred`.

- **Интегрированная авторизация VK**: Реализован полный цикл получения токенов (VK Calls -> OK.ru -> TURN credentials) внутри Go.
  - Использование `turnHTTPClient` с protected sockets

- **Кэширование TURN credentials (per-stream)**: Каждый поток (stream) имеет свой собственный кэш credentials. Это повышает изоляцию и стабильность работы при множественных потоках.
  - `StreamCredentialsCache` — отдельный кэш для каждого stream ID
  - `credentialLifetime = 10 минут`, `cacheSafetyMargin = 60 секунд`
  - `maxCacheErrors = 3`, `errorWindow = 10 секунд` (на каждый поток отдельно)
  - Кэш инвалидируется при смене сети через `wgNotifyNetworkChange()` (все кэши)
  - При 3 auth errors за 10 секунд инвалидируется только кэш конкретного потока
  - `credentialsStore` — централизованное хранилище с RWMutex для потокобезопасности
  - `streamsPerCred` — переменная (по умолчанию 4), задаваемая при старте

- **Разделение получения и кэширования credentials**:
  - `getVkCreds()` — управляет кэшированием (проверка, чтение, запись)
  - `fetchVkCreds()` — выполняет HTTP-запросы к VK/OK API без блокировки кэша
  - RWMutex позволяет параллельное чтение кэша несколькими горутинами

- **Защита сокетов**: Все исходящие соединения (HTTP, UDP, TCP) используют `Control` функцию с вызовом `wgProtectSocket`.
  - `protectControl()` — обёртка для syscall.RawConn

- **Custom DNS Resolver**: Встроенный резолвер с обходом системных DNS Android (localhost) для обеспечения работоспособности в условиях активного VPN.
  - Каскадный fallback: UDP (53) → DoH (443) → DoT (853)
  - DNS сервер: `77.88.8.8` (Yandex DNS)
  - DoH endpoint: `https://common.dot.dns.yandex.net/dns-query`
  - DoT endpoint: `77.88.8.8:853`
  - `hostCache` с TTL 5 минут для кэширования resolved адресов
  - `protectedResolverMu` мьютекс для потокобезопасной замены
  - Все DNS запросы используют `protectControl()` для защиты сокетов

- **Таймаут DTLS handshake**: Явный 10-секундный таймаут предотвращает зависания при потере пакетов.
  - `dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))`

- **Staggered запуск потоков**: Потоки запускаются с задержкой 200ms для снижения нагрузки на сервер и предотвращения "шторма" подключений.
  - `time.Sleep(200 * time.Millisecond)` между запусками

- **Watchdog реконнекта**: Автоматическое восстановление соединения при отсутствии ответа в течение 30 секунд.
  - Проверка `time.Since(lastRx.Load()) > 30*time.Second` в TX goroutine

- **Метрики для диагностики**: Счётчики ошибок для отслеживания проблем (dtlsTxDropCount, dtlsRxErrorCount, relayTxErrorCount, relayRxErrorCount, noDtlsTxDropCount, noDtlsRxErrorCount).
  - `atomic.Uint64` для потокобезопасности

- **Улучшенная обработка ошибок аутентификации**: Функции `isAuthError()` и `handleAuthError()` для детектирования и обработки устаревших credentials.
  - Детектирование по строкам: "401", "Unauthorized", "authentication", "invalid credential", "stale nonce"

- **Deadline management**: Явные дедлайны для handshake (10с), session ID (5с) и обновления дедлайнов каждые 5с (30с таймаут).
  - Deadline updater goroutine обновляет каждые 5 секунд

- **Connected UDP/TCP abstraction**: Интерфейс `net.PacketConn` для унификации обработки UDP и TCP соединений.
  - `connectedUDPConn` обёртка для UDP
  - `turn.NewSTUNConn()` для TCP

- **Packet Pool**: Оптимизация выделения памяти через `sync.Pool` для буферов пакетов (2048 байт).
  - `packetPool.Get()` / `packetPool.Put()`

---

## 2. Слой конфигурации (Java)

### `tunnel/src/main/java/com/wireguard/config/`

- **`Peer.java`**: Поддержка `extraLines` — списка строк, начинающихся с `#@`. Это позволяет хранить метаданные прокси прямо в `.conf` файле, не нарушая совместимость с другими клиентами.
  - Парсинг в `Peer.parse()`: строки `#@` сохраняются через `builder.addExtraLine()`
  - Сериализация в `toWgQuickConfig()`: extraLines выводятся как есть

- **`Config.java`**: Парсер корректно передаёт комментарии с префиксом `#@` в соответствующие секции.

---

## 3. Логика управления и UI (Kotlin)

### `ui/src/main/java/com/wireguard/android/turn/TurnSettings.kt`

- **`TurnSettings`**: Модель данных для настроек прокси.
  - Данные: `enabled`, `peer`, `vkLink`, `mode`, `streams`, `useUdp`, `localPort`, `turnIp`, `turnPort`, `peerType`, `streamsPerCred`
  - `peerType`: `"proxy_v2"` (по умолчанию), `"proxy_v1"`, `"wireguard"`
  - `streamsPerCred`: количество потоков на один кэш credentials (по умолчанию 4)
  - Методы: `toComments()`, `fromComments()`, `validate()`
  - **Обратная совместимость**: при чтении legacy конфигов с `#@wgt:NoDTLS = true` автоматически выставляется `peerType = "wireguard"`

### `ui/src/main/java/com/wireguard/android/viewmodel/TurnSettingsProxy.kt`

- **`TurnSettingsProxy`**: Observable ViewModel для Data Binding.
  - Все поля с `@Bindable` аннотацией
  - `peerType: String = "proxy_v2"`, `streamsPerCred: String = "4"`
  - `advancedExpanded: Boolean` — состояние сворачивания Advanced секции
  - Метод `resolve()` — валидация и преобразование в `TurnSettings`

### `ui/src/main/java/com/wireguard/android/turn/TurnConfigProcessor.kt`

- Логика инъекции/извлечения настроек из текста конфигурации.
  - `injectTurnSettings()` — добавляет комментарии `#@wgt:` в первый Peer
  - `extractTurnSettings()` — извлекает настройки из комментариев
  - `modifyConfigForActiveTurn()` — модифицирует конфиг для активного TURN:
    - MTU = 1280 (фиксировано)
    - Endpoint = `127.0.0.1:localPort`
    - PersistentKeepalive = 25 (если `peerType != "wireguard"`) или оригинальное (если `peerType == "wireguard"`)

### `ui/src/main/java/com/wireguard/android/turn/TurnProxyManager.kt`

- **`TurnProxyManager`**: Управляет нативным процессом прокси.

  **Синхронизация при запуске:**
  - Вызывает `TurnBackend.waitForVpnServiceRegistered(2000)` для ожидания регистрации JNI
  - После подтверждения JNI запускает `wgTurnProxyStart()` с параметрами `peerType`, `streamsPerCred`, `networkHandle`
  - Это гарантирует что `VpnService.protect()` будет работать для всех сокетов TURN

  **PhysicalNetworkMonitor:**
  - Отдельный класс `PhysicalNetworkMonitor` отслеживает физические сети (WiFi, Cellular)
  - Игнорирует VPN интерфейсы для избежания обратной связи с собственным туннелем
  - Приоритет выбора: WiFi > Cellular > любая другая сеть с интернетом
  - Debounce 1500ms через Flow для фильтрации быстрых переключений
  - `currentNetwork` — синхронное получение текущего лучшей сети без debounce
  - `bestNetwork` — Flow с debounce 1500ms и distinctUntilChanged

  **Автоматический рестарт:**
  - При смене физического типа сети (WiFi ↔ Cellular) TURN переподключается без участия пользователя
  - Вызывает `wgNotifyNetworkChange()` для сброса DNS/HTTP в Go слое
  - Экспоненциальный backoff при неудачах: 2с → 5с → 15с (при более 5 попытках)
  - Флаг `userInitiatedStop` — не рестартировать, если пользователь явно остановил туннель
  - `operationMutex` — мьютекс для сериализации операций start/stop и предотвращения гонок

  **Логирование:**
  - Встроенный лог через `StringBuilder` с ограничением 128KB
  - Методы: `getLog()`, `clearLog()`, `appendLogLine()`

  **Управление жизненным циклом:**
  - `onTunnelEstablished()` — вызывается после создания туннеля
  - `stopForTunnel()` — остановка с сбросом состояния и VpnService reference
  - `isRunning()` — проверка статуса прокси

### `tunnel/src/main/java/com/wireguard/android/backend/TurnBackend.java`

- **AtomicReference для CompletableFuture**: Атомарная замена `CompletableFuture<VpnService>` через `getAndSet()` предотвращает гонки при быстрой смене состояний сервиса.
  - `vpnServiceFutureRef` — хранит текущий Future
  - `getAndSet(new CompletableFuture<>)` — атомарная замена на новый

- **CountDownLatch для синхронизации JNI**: Latch сигнализирует что JNI зарегистрирован и готов защищать сокеты.
  - `vpnServiceLatchRef` — AtomicReference с CountDownLatch
  - `countDown()` вызывается после `wgSetVpnService()`

- **`waitForVpnServiceRegistered(timeout)`**: Метод для ожидания регистрации JNI перед запуском TURN прокси.
  - `await(timeout, TimeUnit.MILLISECONDS)` на latch
  - Возвращает `true` при успехе, `false` при timeout/interrupt

- **`wgNotifyNetworkChange()`**: Native функция для сброса DNS/HTTP при смене сети.

- **`wgTurnProxyStart(...)`**: Native функция запуска TURN прокси.
  - Параметры: `peerAddr`, `vklink`, `mode`, `n`, `useUdp`, `listenAddr`, `turnIp`, `turnPort`, `peerType`, `streamsPerCred`, `networkHandle`

- **`onVpnServiceCreated()`**: Метод регистрации VpnService в JNI.
  - При `service != null`: `wgSetVpnService()` → `latch.countDown()` → `future.complete()`
  - При `service == null`: сброс future и latch для следующего цикла

### `tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java`

- **Правильный порядок инициализации VpnService:**
  1. В `onCreate()` сначала вызывается `TurnBackend.onVpnServiceCreated(this)` для регистрации в JNI
  2. Затем завершается `vpnService.complete(this)` для Java кода
  - Это гарантирует что JNI готов до того как TurnProxyManager получит Future

- **TURN запускается после создания туннеля:**
  - В `setStateInternal()` TURN прокси запускается после `builder.establish()`
  - Это гарантирует что `VpnService.protect()` будет работать для сокетов TURN
  - Логирование: `"Tunnel established, TURN proxy should be started now"`

- **Защита сокетов WireGuard:**
  - `service.protect(wgGetSocketV4(currentTunnelHandle))`
  - `service.protect(wgGetSocketV6(currentTunnelHandle))`
  - Вызывается ДО запуска TURN прокси

### `ui/src/main/java/com/wireguard/android/model/TunnelManager.kt`

- **Запуск TURN после создания туннеля:**
  - TURN прокси запускается через `TurnProxyManager.onTunnelEstablished()` после того как `GoBackend.setStateInternal()` завершит создание туннеля

---

## 4. Протокол взаимодействия

Для обеспечения стабильности соединения в условиях мультиплексирования (Multi-Stream) используется следующий протокол:

1. **DTLS Handshake**: Стандартное установление защищенного соединения (с таймаутом 10 секунд).
   - Генерация self-signed сертификата один раз на все потоки
   - Cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
   - Connection ID Generator: `OnlySendCIDGenerator()`

2. **Session Identification** (только Proxy v2): Клиент отправляет 17 байт в DTLS поток:
   - 16 байт — Session ID (UUID, генерируется при каждом запуске)
   - 1 байт — Stream ID (номер потока 0..n-1)
   - Отправка происходит сразу после успешного handshake
   - **Proxy v1** пропускает этот шаг

3. **Tunnel Traffic**: После handshake начинается двусторонний обмен пакетами WireGuard.
   - Round-robin распределение по готовым потокам
   - Watchdog 30 секунд на отсутствие RX

Это позволяет прокси-серверу идентифицировать сессию пользователя и поддерживать стабильный `Endpoint` на стороне WireGuard сервера, вне зависимости от количества активных DTLS-потоков или смены IP-адресов клиента.

**Режим WireGuard (`peerType = "wireguard"`):**
- Пропускается DTLS handshake и Session ID handshake
- Прямой relay между WireGuard клиентом и сервером через TURN
- Не совместим с прокси-сервером, требующим Session ID

---

## 5. Формат метаданных в конфигурации

Для хранения настроек используются специально размеченные комментарии в секции `[Peer]`:

```ini
[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = false
#@wgt:IPPort = 1.2.3.4:56000
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:Mode = vk_link
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:PeerType = proxy_v2          # proxy_v2 | proxy_v1 | wireguard
#@wgt:StreamsPerCred = 4           # потоков на один кэш credentials
#@wgt:TurnIP = 1.2.3.4             # (optional) Override TURN server IP
#@wgt:TurnPort = 12345             # (optional) Override TURN server port
```

**Обратная совместимость:**
- При чтении legacy конфигов с `#@wgt:NoDTLS = true` автоматически устанавливается `peerType = "wireguard"`
- Если `NoDTLS` не указан или `false` — `peerType = "proxy_v2"`

**Обработка extraLines:**
- Строки начинающиеся с `#@` сохраняются в `Peer.extraLines`
- `TurnConfigProcessor.injectTurnSettings()` добавляет комментарии с префиксом `#@wgt:`
- `TurnConfigProcessor.extractTurnSettings()` извлекает настройки из комментариев
- При сериализации в `toWgQuickConfig()` extraLines выводятся как есть

---

## 6. Расширенные настройки TURN

### TurnIP и TurnPort

Позволяют переопределить адрес TURN сервера, полученный из VK/OK API. Полезно для:
- Подключения к конкретному серверу TURN
- Обхода проблем с маршрутизацией
- Тестирования инфраструктуры

**Пример:**
```
#@wgt:TurnIP = 155.212.199.166
#@wgt:TurnPort = 19302
```

**Логика применения (turn-client.go):**
- Если `turnIp != ""` и `turnPort != 0`: адрес = `turnIp:turnPort`
- Если `turnIp != ""` и `turnPort == 0`: порт берётся из оригинального адреса
- Если `turnIp == ""` и `turnPort != 0`: хост берётся из оригинального адреса

### Peer Type

Определяет режим работы TURN прокси:

| Тип | DTLS | Session ID Handshake | Описание |
|-----|------|---------------------|----------|
| `proxy_v2` | Да | Да | Полный режим с DTLS и агрегацией потоков на сервере |
| `proxy_v1` | Да | Нет | DTLS без передачи Session ID/Stream ID |
| `wireguard` | Нет | Нет | Прямой relay без DTLS (для отладки или прямого подключения) |

**Пример:**
```
#@wgt:PeerType = proxy_v2
```

### Streams Per Credentials

Количество потоков, разделяющих один кэш credentials. По умолчанию 4. Уменьшение повышает изоляцию, увеличение — снижает частоту запросов к API.

**Пример:**
```
#@wgt:StreamsPerCred = 4
```

### Watchdog Timeout

Таймаут неактивности для DTLS режима (в секундах). Если в течение указанного времени не получено ни одного пакета от TURN сервера (RX), передача пакетов (TX) прекращается до восстановления соединения.

**Значения:**
- `0` — watchdog отключен (по умолчанию)
- `≥5` — таймаут в секундах

**Пример:**
```
#@wgt:WatchdogTimeout = 30
```

**Принцип работы:**
- Применяется только в режиме DTLS (`peerType != "wireguard"`)
- Проверяется время последнего полученного пакета (RX) перед отправкой каждого пакета (TX)
- Если разница превышает watchdogTimeout секунд, TX goroutine завершается с логом `[STREAM X] TX watchdog timeout (Xs)`
- Это приводит к реконнекту через 1 секунду и получению новых credentials
- В режиме без DTLS (wireguard) watchdog не используется

**Назначение:**
- Обнаружение "зависших" DTLS соединений
- Быстрое восстановление после длительных потерь сети
- Предотвращение отправки пакетов в мертвое соединение

### PersistentKeepalive (автоматический)

При включённом DTLS режиме (`peerType != "wireguard"`), `TurnConfigProcessor.modifyConfigForActiveTurn` **автоматически устанавливает PersistentKeepalive=25** для всех пиров.

**Назначение:**
- Поддержание NAT mapping для DTLS соединения
- Предотвращение таймаута UDP сессии на стороне TURN сервера
- Значение 25 секунд выбрано как оптимальный баланс между нагрузкой и надёжностью

**Логика:**
- Если в конфиге уже указан PersistentKeepalive ≤ 25, используется оригинальное значение
- Если PersistentKeepalive не указан или > 25, устанавливается 25
- В режиме WireGuard (`peerType = "wireguard"`) PersistentKeepalive не модифицируется

**Пример (автоматически добавляется):**
```
[Peer]
PublicKey = <key>
Endpoint = 127.0.0.1:9000
PersistentKeepalive = 25
```

---

## 7. Хранение настроек

### TurnSettingsStore

Настройки TURN сохраняются в отдельном JSON-файле `<tunnel>.turn.json` в директории приложения. Это позволяет:
- Хранить настройки независимо от конфига
- Обновлять конфиг без потери настроек TURN
- Быстро загружать/применять настройки

**Формат файла:**
```json
{
  "enabled": true,
  "peer": "89.250.227.41:56000",
  "vkLink": "https://vk.com/call/join/...",
  "mode": "vk_link",
  "streams": 4,
  "useUdp": false,
  "localPort": 9000,
  "turnIp": "",
  "turnPort": 0,
  "peerType": "proxy_v2",
  "streamsPerCred": 4
}
```

**Обратная совместимость:**
- При загрузке JSON проверяется наличие legacy поля `noDtls`
- Если `noDtls = true` и `peerType` отсутствует — автоматически устанавливается `peerType = "wireguard"`

**Методы TurnSettingsStore:**
- `load(name: String)` — загрузка из JSON файла
- `save(name: String, settings: TurnSettings?)` — сохранение в JSON файл
- `delete(name: String)` — удаление файла настроек
- `rename(name: String, replacement: String)` — переименование файла

**Расположение файлов:**
- Путь: `<context.filesDir>/<tunnel>.turn.json`
- Пример: `/data/data/com.wireguard.android/files/mytunnel.turn.json`

---

## 8. Архитектура запуска TURN

```
GoBackend.setStateInternal()
  → builder.establish()                    ← Туннель создан
  → wgTurnOn()                             ← Go backend запущен
  → service.protect() для сокетов WireGuard
  → TurnProxyManager.onTunnelEstablished() ← TURN запускается ПОСЛЕ туннеля
    → PhysicalNetworkMonitor.currentNetwork ← Получение текущего network handle
    → TurnBackend.waitForVpnServiceRegistered() ← Ждём JNI
    → wgTurnProxyStart(..., peerType, streamsPerCred, watchdogTimeout, networkHandle)
      → update_current_network() в JNI      ← Кэширование Network object
      → wgNotifyNetworkChange()             ← Инициализация resolver и HTTP client
      → VK Auth для получения credentials
      → Подключение к TURN серверу (N потоков)
      → DTLS handshake для каждого потока  ← 10с таймаут
      → Session ID handshake (17 байт)     ← только для proxy_v2
      → wgProtectSocket() + bindSocket() для всех сокетов
```

**Преимущества:**
- TURN запускается после создания туннеля, что гарантирует работу `VpnService.protect()` для всех сокетов
- Явная синхронизация через CountDownLatch исключает гонки условий
- Сокеты WireGuard защищаются до запуска TURN
- **networkHandle** передаётся в Go для привязки сокетов к конкретному Network через `bindSocket()`
- **PhysicalNetworkMonitor** отслеживает физические сети и автоматически перезапускает TURN при смене типа сети
- **peerType** и **streamsPerCred** передаются из настроек туннеля

**Временные параметры:**
- Timeout ожидания JNI: 2000ms
- Задержка между запусками потоков: 200ms
- Timeout DTLS handshake: 10s
- Timeout ожидания ready потока: 30s
- Watchdog реконнекта: 30s
- Debounce network change: 1500ms

---

## 9. PhysicalNetworkMonitor

### Расположение
`ui/src/main/java/com/wireguard/android/turn/PhysicalNetworkMonitor.kt`

### Назначение
Мониторинг физических сетей (WiFi, Cellular) для автоматического перезапуска TURN при смене типа подключения.

### Ключевые особенности

**Приоритет сетей:**
1. WiFi (TRANSPORT_WIFI)
2. Cellular (TRANSPORT_CELLULAR)
3. Любая другая физическая сеть с интернетом

**Фильтрация:**
- Игнорирует VPN транспорты (`TRANSPORT_VPN`) — предотвращает обратную связь с собственным туннелем
- Требует `NET_CAPABILITY_INTERNET` — только сети с доступом в интернет
- Требует `NET_CAPABILITY_NOT_VPN` — исключает VPN из рассмотрения

**Debounce и стабильность:**
- `bestNetwork` Flow с debounce **1500ms** — фильтрация быстрых переключений
- `distinctUntilChanged()` — только уникальные изменения
- `currentNetwork` — синхронное получение текущего значения без debounce

**NetworkCallback:**
- `onCapabilitiesChanged()` — синхронизация capabilities, добавление/удаление из ConcurrentHashMap
- `onLost()` — удаление сети из мониторинга
- `update()` — применение логики приоритетов и обновление `_bestNetwork`

**Жизненный цикл:**
- `start()` — регистрация callback, инициализация текущего состояния
- `stop()` — отписка callback, очистка ConcurrentHashMap

### Интеграция с TurnProxyManager

```kotlin
val networkMonitor = PhysicalNetworkMonitor(context)
networkMonitor.start()

scope.launch {
    networkMonitor.bestNetwork.collectLatest { network ->
        if (network != null) {
            handleNetworkChange(network)
        }
    }
}
```

**Логика рестарта:**
1. Сохранение baseline сети при запуске туннеля
2. Игнорирование одинаковых сетей (стабильность)
3. При реальном изменении — вызов `performRestartSequence()`
4. Рестарт: stop → wgNotifyNetworkChange() → delay(500) → start

### Преимущества

- **Централизованный мониторинг** — отдельный класс для отслеживания физических сетей
- **Приоритизация** — явный выбор WiFi > Cellular
- **Flow-based** — реактивный подход с debounce через Kotlin Flow
- **Игнорирование VPN** — явная фильтрация VPN транспортов
- **ConcurrentHashMap** — потокобезопасное хранение сетей

**Технические детали:**
- `networks: ConcurrentHashMap<Network, NetworkCapabilities>` — хранение всех доступных сетей
- `callback: ConnectivityManager.NetworkCallback` — системный callback для событий сети
- `request: NetworkRequest` — запрос с `NET_CAPABILITY_INTERNET` и `NET_CAPABILITY_NOT_VPN`
- `cm.allNetworks.forEach` — начальное заполнение при `start()`

---

## 10. Режимы получения credentials

### Обзор

TURN клиент поддерживает два режима получения TURN credentials, выбираемых через UI:

| Параметр | VK Link | WB |
|----------|---------|-----|
| **Описание** | Получение кредов через VK/OK API | Получение кредов через WB Stream (LiveKit ICE) |
| **Требует vkLink** | Да (ссылка на VK call) | Нет |
| **Протокол** | HTTP API VK/OK | WebSocket + LiveKit ICE |
| **Файл** | `vk.go` | `wb.go` |

### UI выбор режима

В редакторе туннеля (TunnelEditorFragment) добавлен **Spinner** для выбора режима TURN сервера:
- **VK Link** — отображается поле для ввода VK Calls link
- **WB** — поле VK Link скрыто (не требуется)

### Режим VK Link

При `mode = "vk_link"`:
1. Пользователь вводит ссылку на VK call (например `https://vk.ru/call/join/...`)
2. `getVkCreds()` выполняет цепочку API вызовов:
   - Token 1: `login.vk.ru/?act=get_anonym_token` (messages anonym_token)
   - getCallPreview: `api.vk.ru/method/calls.getCallPreview`
   - Token 2: `api.vk.ru/method/calls.getAnonymousToken`
   - Token 3: `calls.okcdn.ru/fb.do` (auth.anonymLogin)
   - Token 4: `calls.okcdn.ru/fb.do` (vchat.joinConversationByLink → TURN credentials)
3. Полученные credentials (username, password, serverAddr) кэшируются на 10 минут

**Файл:** `tunnel/tools/libwg-go/vk.go`

### Режим WB

При `mode = "wb"`:
1. `wbFetch()` не требует vkLink (параметр игнорируется)
2. Выполняется полный цикл WB Stream:
   - Guest register: `/auth/api/v1/auth/user/guest-register`
   - Create room: `/api-room/api/v2/room`
   - Join room: `/api-room/api/v1/room/{roomId}/join`
   - Get room token: `/api-room-manager/api/v1/room/{roomId}/token`
   - LiveKit ICE: WebSocket `wss://wbstream01-el.wb.ru:7880/rtc` → парсинг protobuf → TURN credentials
3. Полученные credentials кэшируются на 10 минут

**Файл:** `tunnel/tools/libwg-go/wb.go`

### Архитектура выбора режима

**Go backend (`turn-client.go`):**
```go
var globalGetCreds getCredsFunc  // Глобальная функция для получения кредов

func wgTurnProxyStart(..., modeC *C.char, ...) int32 {
    mode := C.GoString(modeC)

    if mode == "wb" {
        globalGetCreds = func(ctx, link, streamID) {
            return getCredsCached(ctx, link, streamID, wbFetch)
        }
    } else {
        globalGetCreds = func(ctx, lk, streamID) {
            return getCredsCached(ctx, lk, streamID, func(ctx, l) {
                return getVkCreds(ctx, l, streamID)
            })
        }
    }
}
```

**Stream.run()** использует `globalGetCreds` вместо жёсткого вызова `getVkCreds`:
```go
func (s *stream) run(link string, ...) {
    user, pass, addr, err := globalGetCreds(sCtx, link, s.id)
    // ...
}
```

### Разделение файлов Go backend

Для лучшей организации кода `turn-credentials.go` разделён на три файла:

| Файл | Содержимое |
|------|------------|
| `credentials.go` | Общие типы (`TurnCredentials`, `StreamCredentialsCache`), кэширование (`getCredsCached`, `serializeFetch`), `fetchMu`, переменная `streamsPerCred` |
| `vk.go` | VK-специфичная логика (`VKCredentials`, `getVkCreds`, `fetchVkCreds`, `getTokenChain`, `vkDelayRandom`) |
| `wb.go` | WB-специфичная логика (`WbTurnCred`, `wbFetch`, `fetchWbCreds`, `wbLkICE`, протобуф-парсеры `wbPbVar`, `wbPbAll`, `wbPbStr`, `wbPbICE`, `wbDedup`) |

---

## 11. VK Auth Flow

### Кэширование credentials

**Краткая информация:**

- Каждый поток имеет свой собственный кэш credentials (per-stream)
- TTL: 10 минут, safety margin: 60 секунд
- При 3 auth errors за 10 секунд инвалидируется только кэш конкретного потока
- При смене сети инвалидируются все кэши
- `streamsPerCred` потоков разделяют один кэш (по умолчанию 4)

**Подробная информация:** См. раздел [14. Per-Stream Кэширование Credentials](#14-per-stream-кэширование-credentials)

### Обработка ошибок аутентификации

**Детектирование auth error:**
- Строки в ошибке: "401", "Unauthorized", "authentication", "invalid credential", "stale nonce"
- Функция `isAuthError(err)` проверяет текст ошибки

**Логика:**
- Счётчик ошибок на каждый поток отдельно (sliding window 10 секунд)
- При 3 ошибках: инвалидация кэша только этого потока
- Логи: `[STREAM X] Auth error (count=N/3)`

---

## 12. Метрики и диагностика

### Счётчики ошибок (atomic.Uint64/atomic.Int32)

- `dtlsTxDropCount` (atomic.Uint64) — пакеты, отброшенные в DTLS TX goroutine
- `dtlsRxErrorCount` (atomic.Uint64) — ошибки в DTLS RX goroutine
- `relayTxErrorCount` (atomic.Uint64) — ошибки записи в relay connection
- `relayRxErrorCount` (atomic.Uint64) — ошибки чтения из relay connection
- `noDtlsTxDropCount` (atomic.Uint64) — пакеты, отброшенные в WireGuard режиме
- `noDtlsRxErrorCount` (atomic.Uint64) — ошибки в WireGuard RX goroutine

**Per-stream счётчики (в StreamCredentialsCache):**
- `errorCount` (atomic.Int32) — счётчик auth ошибок для конкретного потока (сбрасывается при успехе или после 10 секунд)
- `lastErrorTime` (atomic.Int64) — время последней auth ошибки для sliding window (на каждый поток)

### Логирование

**Уровни логирования:**
- `ANDROID_LOG_INFO` — успешные операции (handshake SUCCESS, protect SUCCESS)
- `ANDROID_LOG_ERROR` — ошибки (protect FAILED, auth errors, timeouts)
- `ANDROID_LOG_WARN` — предупреждения (например, network not found)

**Основные теги:**
- `WireGuard/TurnClient` — основное логирование TURN клиента (Go)
- `WireGuard/TurnProxyManager` — логирование на уровне Kotlin (TurnProxyManager)
- `WireGuard/TurnBackend` — JNI слой (Java)
- `WireGuard/GoBackend` — Go backend
- `WireGuard/JNI` — JNI функции (защита сокетов, bindSocket)
- `WireGuard/TurnSettingsStore` — хранение настроек TURN
- `WireGuard/DNS` — DNS resolver (кэширование, запросы)

**Формат логов:**
```
[PROXY] Hub starting on 127.0.0.1:9000 (streams=4, mode=vk_link, peerType=proxy_v2, streamsPerCred=4, networkHandle=12345)
[VK Auth] Using cached credentials (expires in 5m30s)
[STREAM 0] Dialing TURN server 1.2.3.4:56000...
[STREAM 0] DTLS handshake SUCCESS
[STREAM 0] TX watchdog timeout
[NETWORK] Network change notified: resolver reset
[DNS] UDP success: vpn.example.com -> 192.168.1.100
[JNI] wgProtectSocket(fd=123): SUCCESS (protected + bound to net 72057594037927936)
```

---

## 13. DNS Resolver

### Расположение
`tunnel/tools/libwg-go/turn-dns-resolver.go`

### Назначение
Обход системных DNS Android (которые могут не работать через VPN) для разрешения доменных имён TURN серверов и API endpoints.

### Архитектура

**Список DNS серверов:**
При запуске прокси формируется финальный список `dnsServers`:
```
dnsServers = systemDns + dnsServersPredefined
```
- **systemDns** — системные DNS серверы, полученные из `LinkProperties` текущего сетевого соединения (WiFi/4G)
- **dnsServersPredefined** — предустановленные fallback серверы (Yandex + Google)

Если системные DNS недоступны, используются только predefined.

**Каскадный fallback для каждого сервера:**
1. **UDP (порт 53)** — стандартный DNS запрос, самый быстрый
2. **DoH (порт 443)** — DNS-over-HTTPS, fallback если UDP заблокирован
3. **DoT (порт 853)** — DNS-over-TLS, последний fallback

**Predefined серверы:**
- DNS сервер: `77.88.8.8` (Yandex DNS)
- DoH: `https://common.dot.dns.yandex.net/dns-query` (`77.88.8.8:443`)
- DoT: `77.88.8.8:853` (ServerName: `common.dot.dns.yandex.net`)
- Google: `8.8.8.8` (Plain + DoH)

### DnsCache

**Параметры:**
- `cacheTTL = 5 минут` — время жизни записи в кэше
- `dnsTimeout = 2 секунды` — таймаут для UDP DNS
- `dohTimeout = 5 секунд` — таймаут для DoH
- `dotTimeout = 5 секунд` — таймаут для DoT

**Методы:**
- `Resolve(ctx, domain)` — разрешение домена с кэшированием
- `ClearCache()` — очистка кэша (вызывается при смене сети)
- `InitSystemDns(servers []string)` — инициализация системных DNS при старте прокси

### Получение системных DNS

Системные DNS извлекаются из `Network` объекта через JNI:
1. `ConnectivityManager.getLinkProperties(network)` → `LinkProperties`
2. `LinkProperties.getDnsServers()` → `List<InetAddress>`
3. IP адреса передаются в Go как строка через запятую
4. `InitSystemDns()` добавляет их в начало списка `dnsServers`

**JNI функции:**
- `Java_TurnBackend_wgGetNetworkDnsServers(networkHandle)` — Java native метод
- `getNetworkDnsServers(network_handle)` — C функция, вызываемая из Go

### Интеграция

**VK Auth Flow:**
- Все HTTP запросы к VK API используют `hostCache.Resolve()` для разрешения доменов
- DNS resolution происходит перед каждым запросом при отсутствии в кэше
- TURN server address resolution в `getVkCreds()` после получения credentials

**Логирование:**
```
[DNS] Trying UDP for api.vk.ru
[DNS] UDP success: api.vk.ru -> 93.186.234.10
[TURN DNS] Resolved TURN server relay.example.com -> 155.212.199.166
[DNS] Cache cleared
```

### Защита сокетов

Все DNS запросы используют `protectControl()` для защиты сокетов через `VpnService.protect()`:
- UDP dialer с `Control: protectControl`
- DoH/DoT dialer с `protectAndDial()`

Это гарантирует что DNS трафик обходит VPN туннель и идёт через физический интерфейс.

### Особенности реализации

**DNS query format:**
- A record запрос (TYPE=1, CLASS=IN)
- Random ID для каждого запроса
- Стандартный рекурсивный запрос

**DoH:**
- HTTP/2 приоритет (per RFC 8484)
- Content-Type: `application/dns-message`
- Accept: `application/dns-message`

**DoT:**
- 2-byte length prefix перед DNS query
- TLS handshake с явным ServerName
- Минимальная версия TLS 1.2

---

## 14. Per-Stream Кэширование Credentials

### Архитектура

**Структуры данных:**

```go
// StreamCredentialsCache — кэш одного потока
type StreamCredentialsCache struct {
    creds         TurnCredentials      // Username, Password, ServerAddr, ExpiresAt, Link
    mutex         sync.RWMutex         // Защита кэша
    errorCount    atomic.Int32         // Счётчик auth ошибок
    lastErrorTime atomic.Int64         // Время последней ошибки
}

// credentialsStore — хранилище всех кэшей
var credentialsStore = struct {
    mu     sync.RWMutex
    caches map[int]*StreamCredentialsCache  // cacheID -> cache
}{
    caches: make(map[int]*StreamCredentialsCache),
}

var streamsPerCred = 4 // Количество потоков на один кэш (задаётся из Java)
```

**Диаграмма потокобезопасности:**

```
credentialsStore (RWMutex)
├── StreamCredentialsCache[0] (RWMutex)  ← потоки 0,1,2,3 (при streamsPerCred=4)
│   ├── creds
│   ├── errorCount (atomic)
│   └── lastErrorTime (atomic)
├── StreamCredentialsCache[1] (RWMutex)  ← потоки 4,5,6,7
└── StreamCredentialsCache[2] (RWMutex)  ← потоки 8,9,10,11
```

**Формула cacheID:**
```go
func getCacheID(streamID int) int {
    return streamID / streamsPerCred
}
```

### Функции

**`getStreamCache(streamID int) *StreamCredentialsCache`**:
- Возвращает существующий кэш или создаёт новый
- Использует double-check locking для потокобезопасности
- Сначала RLock для быстрого пути (чтение)
- При отсутствии — Lock и повторная проверка

**`getVkCreds(ctx, link, streamID)`**:
1. `getStreamCache(streamID)` — получение кэша
2. `RLock()` — проверка валидности credentials
3. Если кэш валиден — возврат из кэша
4. Если кэш невалиден — `fetchVkCreds()` без блокировки
5. `Lock()` — запись новых credentials в кэш

**`fetchVkCreds(ctx, link, streamID)`**:
- HTTP-запросы к VK API и OK.ru
- Разрешение доменов через `hostCache.Resolve()`
- Возвращает username, password, serverAddr

**`handleAuthError(streamID int)`**:
- Инкремент счётчика ошибок для потока
- Проверка sliding window (10 секунд)
- При 3 ошибках — вызов `cache.invalidate(streamID)`

**`invalidate(streamID int)`**:
- Очистка credentials кэша
- Сброс счётчика ошибок и таймера
- Логирование с указанием streamID

**`invalidateAllCaches()`**:
- Инвалидация всех кэшей (при смене сети)
- Очистка map для освобождения памяти
- Логирование с указанием `streamsPerCred`

### Сценарии использования

**Нормальная работа:**
1. Поток 0 запрашивает credentials — кэш пуст — fetchVkCreds() — запись в кэш
2. Поток 1 запрашивает credentials — кэш тот же (cacheID=0) — возврат из кэша (быстро)
3. Поток 4 запрашивает credentials — кэш пуст (cacheID=1) — fetchVkCreds() — запись в кэш
4. Все потоки reconnect — кэш валиден — возврат из кэша (быстро)

**Auth ошибка на одном потоке:**
1. Поток 0: ошибка 1 — счётчик = 1
2. Поток 1: кэш валиден — работает нормально (тот же cacheID)
3. Поток 0: ошибка 2 — счётчик = 2
4. Поток 0: ошибка 3 — инвалидация кэша cacheID=0
5. Поток 0: следующий reconnect — fetchVkCreds() — новый кэш
6. Поток 1: кэш инвалидирован — тоже fetchVkCreds()

**Смена сети:**
1. `wgNotifyNetworkChange()` вызван
2. `invalidateAllCaches()` — все кэши инвалидируются
3. `ClearCache()` — очистка DNS кэша
4. Все потоки выполняют fetchVkCreds() при следующем reconnect

### Преимущества

- **Изоляция**: Ошибка на одном кэше не влияет на другие кэши
- **Параллелизм**: RWMutex позволяет concurrent read
- **Производительность**: HTTP-запросы без блокировки кэша
- **Гибкость**: `streamsPerCred` настраивается (1-16)
- **Память**: Максимум `ceil(16 / streamsPerCred)` кэшей × ~100 байт

---

## 15. UI Структура карточки TURN

### Редактор туннеля (TunnelEditorFragment)

Карточка TURN разделена на три секции:

**1. Peer**
- **Peer type** — Dropdown: Proxy v2 / Proxy v1 / WireGuard
- **Peer address** — поле ввода IP:Port (адрес прокси или WireGuard сервера)

**2. TURN Server**
- **Mode** — Dropdown: VK Link / WB
- **VK Calls link** — поле ввода (видно только при Mode = VK Link)
- **Streams** — количество потоков (1-16)
- **Use UDP** — переключатель

**3. Advanced Settings** (сворачиваемая)
- **Turn IP** — переопределение IP TURN сервера (auto)
- **Turn Port** — переопределение порта TURN сервера (auto)
- **Local port** — локальный порт прослушивания (по умолчанию 9000)
- **Streams per credentials** — потоков на один кэш credentials (по умолчанию 4)

### Просмотр туннеля (TunnelDetailFragment)

Карточка TURN отображает:
- **Peer type** — текущий тип (Proxy v2 / Proxy v1 / WireGuard)
- **Peer address** — адрес пира
- **Mode** — режим (VK Link / WB)
- **Options** — UDP: true/false, Streams: N, Streams/Cred: N

Ссылка VK Calls link в карточке просмотра не отображается.

---

## 16. VK Captcha с WebView Fallback

### Обзор

При получении ошибки `error_code:14` (требуется капча) от VK API во время получения токенов, приложение сначала пытается решить капчу автоматически, а при неудаче открывает `WebView` с страницей `not_robot_captcha`.

### Архитектура

**Поток обработки:**

```
VK API возвращает error_code:14
    ↓
ParseVkCaptchaError() - парсинг ошибки
    ↓
solveVkCaptcha() - запуск решения капчи
    ↓
solveVkCaptchaAutomatic() - попытка автоматического решения
    ├─ Успех → возврат success_token
    └─ Неудача → fallback на WebView
         ↓
    C.requestCaptcha(redirect_uri) - JNI вызов
         ↓
    TurnBackend.onCaptchaRequired(redirectUri) - Java метод
         ↓
    captchaHandler.apply(redirectUri) - вызов обработчика
         ↓
    CaptchaActivity.solveCaptcha() - открытие WebView
         ↓
    Пользователь решает капчу вручную
         ↓
    success_token возвращается в Go
```

### Компоненты

#### 1. Go слой (`vk_captcha.go`)

**`VkCaptchaError`** - структура ошибки капчи:
- `ErrorCode` (14 для капчи)
- `RedirectUri` - URL для открытия WebView
- `SessionToken` - токен сессии из redirect_uri
- `CaptchaSid`, `CaptchaTs`, `CaptchaAttempt` - параметры капчи
- `IsSoundCaptchaAvailable` - флап звуковой капчи

**`solveVkCaptcha(ctx, captchaErr)`** - основная функция:
- Сначала вызывает `solveVkCaptchaAutomatic()` для попытки автоматического решения
- При неудаче вызывает `C.requestCaptcha(redirect_uri)` для открытия WebView
- Использует `captchaMutex` для сериализации (избежание множественных попыток)
- Блокирует поток до получения результата или ошибки

**`solveVkCaptchaAutomatic(ctx, captchaErr)`** - автоматическое решение:
- Извлекает `powInput` и `difficulty` из HTML страницы капчи
- Решает Proof-of-Work (SHA-256 хеш с префиксом из '0')
- Вызывает `captchaNotRobot` API в 4 шага:
  1. `settings` - получение настроек
  2. `componentDone` - отправка fingerprint устройства
  3. `check` - основной запрос с PoW hash и данными курсора
  4. `endSession` - завершение сессии
- Возвращает `success_token` из ответа

#### 2. JNI слой (`jni.c`)

**Глобальные переменные:**
```c
static jclass turn_backend_class_global = NULL;
static jmethodID on_captcha_required_method = NULL;
```

**`requestCaptcha(const char* redirect_uri)`**:
- Вызывается из Go кода при необходимости WebView
- AttachCurrentThread (если поток не прикреплен к JVM)
- Находит `TurnBackend.onCaptchaRequired` метод
- Вызывает Java метод с `redirectUri`
- Копирует результат через `strdup()`
- Освобождает локальные ссылки и отсоединяет поток
- Возвращает `success_token` как C string (caller должен free)

**Инициализация в `wgSetVpnService()`**:
```c
jclass tb_class = (*env)->FindClass(env, "com/wireguard/android/backend/TurnBackend");
turn_backend_class_global = (*env)->NewGlobalRef(env, tb_class);
on_captcha_required_method = (*env)->GetStaticMethodID(
    env, turn_backend_class_global, 
    "onCaptchaRequired", 
    "(Ljava/lang/String;)Ljava/lang/String;"
);
```

#### 3. Java слой (`TurnBackend.java`)

**Поля:**
```java
private static volatile Function<String, String> captchaHandler;
```

**`setCaptchaHandler(Function<String, String> handler)`**:
- Устанавливает обработчик для вызова при необходимости WebView
- Вызывается из `Application.onCreate()`

**`onCaptchaRequired(String redirectUri)`**:
- Статический метод, вызываемый из JNI
- Блокирует поток до получения результата от `captchaHandler`
- Возвращает `success_token` или `null` при ошибке

#### 4. Android UI (`CaptchaActivity.kt`)

**Назначение:** Отображает WebView для ручного решения капчи пользователем.

**Ключевые особенности:**

1. **Привязка к физической сети (bypass VPN):**
   - Использует `ConnectivityManager.bindProcessToNetwork(activeNetwork)`
   - WebView загружает страницу капчи через физический интерфейс, минуя VPN kill-switch
   - При уничтожении активности сетевая привязка сбрасывается

2. **JavaScript перехват:**
   - Инжектирует код для перехвата `XMLHttpRequest` и `fetch` API
   - Отслеживает вызовы `captchaNotRobot.check`
   - Извлекает `success_token` из ответа
   - Вызывает `@JavascriptInterface fun onCaptchaSuccess(token)`

3. **Блокирующий вызов:**
   - `CaptchaActivity.solveCaptcha(context, redirectUri)` - статический метод
   - Запускает `CaptchaActivity` через `startActivity()`
   - Ждет результат через `CompletableDeferred` с таймаутом 5 минут
   - Возвращает `success_token` или `null` при таймауте/ошибке

4. **Обработка ошибок:**
   - `onBackPressed()` - отмена капчи (возврат null)
   - `onDestroy()` - завершение deferred с null если не решена
   - Таймаут 5 минут для избежания бесконечного ожидания

**JavaScript код перехвата:**
```javascript
// Перехват XMLHttpRequest
var originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
    this._url = url;
    return originalOpen.apply(this, arguments);
};

XMLHttpRequest.prototype.send = function(body) {
    var xhr = this;
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr._url.indexOf('captchaNotRobot.check') !== -1) {
            var response = JSON.parse(xhr.responseText);
            if (response.response && response.response.success_token) {
                window.CaptchaCheck.onCaptchaSuccess(response.response.success_token);
            }
        }
    };
    return originalSend.apply(this, arguments);
};

// Перехват fetch API
var originalFetch = window.fetch;
window.fetch = function() {
    var url = arguments[0];
    return originalFetch.apply(this, arguments).then(function(response) {
        if (url.indexOf('captchaNotRobot.check') !== -1) {
            response.clone().json().then(function(data) {
                if (data.response && data.response.success_token) {
                    window.CaptchaCheck.onCaptchaSuccess(data.response.success_token);
                }
            });
        }
        return response;
    });
};
```

#### 5. Регистрация обработчика (`Application.kt`)

В `onCreate()` после загрузки библиотеки:
```kotlin
TurnBackend.setCaptchaHandler { redirectUri ->
    CaptchaActivity.solveCaptcha(applicationContext, redirectUri)
}
```

#### 6. AndroidManifest.xml

Регистрация активности:
```xml
<activity
    android:name=".activity.CaptchaActivity"
    android:exported="false"
    android:theme="@style/Theme.AppCompat.Light.NoActionBar"
    android:configChanges="orientation|screenSize|keyboardHidden" />
```

### VK Auth Flow с капчей

**В `vk.go` - `getTokenChain()`:**

```go
resp, err = doRequest(data, urlAddr)  // calls.getAnonymousToken
if errMsg, ok := resp["error"].(map[string]interface{}); ok {
    captchaErr := ParseVkCaptchaError(errMsg)
    if captchaErr != nil && captchaErr.IsCaptchaError() {
        // Капча обнаруена
        successToken, solveErr := solveVkCaptcha(ctx, captchaErr)
        if solveErr != nil {
            return "", "", "", fmt.Errorf("captcha solving failed: %w", solveErr)
        }
        
        // Повторный запрос с success_token
        data = fmt.Sprintf("vk_join_link=..."+
            "&captcha_sid=%s"+
            "&success_token=%s"+
            "&captcha_ts=%s"+
            "&captcha_attempt=%s"+
            "&access_token=%s",
            captchaErr.CaptchaSid,
            successToken,
            captchaErr.CaptchaTs,
            captchaErr.CaptchaAttempt,
            token1)
        resp, err = doRequest(data, urlAddr)
    }
}
```

### Логирование

```
[VK Auth] Token 2: Captcha detected, solving...
[Captcha] Attempting automatic solution...
[Captcha] PoW input: abc123, difficulty: 2
[Captcha] PoW solved: hash=00a1b2c3...
[Captcha] Step 1/4: settings
[Captcha] Step 2/4: componentDone
[Captcha] Step 3/4: check
[Captcha] Step 4/4: endSession
[Captcha] Automatic solution SUCCESS!

// Или при fallback:
[Captcha] Automatic solution FAILED: captchaNotRobot API failed: timeout
[Captcha] Falling back to WebView...
[Captcha] Opening WebView for manual solving...
WireGuard/JNI: requestCaptcha: called with redirect_uri=https://...
WireGuard/CaptchaActivity: solveCaptcha called with redirectUri=https://...
WireGuard/CaptchaActivity: Loading captcha page: https://...
WireGuard/CaptchaActivity: Captcha interceptor injected
WireGuard/CaptchaActivity: Captcha solved! Got success_token (length=32)
WireGuard/JNI: requestCaptcha: got result token (length=32)
[Captcha] WebView solution SUCCESS! Got success_token
[VK Auth] Token 2: Retrying with captcha solution...
[VK Auth] Token 2 (messages token) received
```

### Строковые ресурсы

```xml
<string name="captcha_title">Verify You Are Human</string>
<string name="captcha_loading">Loading captcha…</string>
<string name="captcha_error">Failed to solve captcha. Please try again.</string>
<string name="captcha_instructions">Please complete the verification to continue</string>
```

### Технические особенности

1. **Сериализация через mutex:** 
   - `captchaMutex` в Go предотвращает одновременные попытки решения капчи
   - Избегает конфликта нескольких потоков TURN

2. **Блокирующий вызов:**
   - Go → JNI → Java вызов блокирует поток до результата
   - Таймаут 5 минут для избежания бесконечного ожидания
   - Использует `CompletableDeferred` + `runBlocking` в Kotlin

3. **Bypass VPN:**
   - `bindProcessToNetwork()` привязывает WebView к физической сети
   - Гарантирует загрузку страницы капчи даже при активном VPN kill-switch
   - Сбрасывается при уничтожении активности

4. **Перехват ответа:**
   - JavaScript инжектируется после загрузки страницы
   - Перехватывает оба API (XMLHttpRequest и fetch)
   - Извлекает `success_token` из JSON ответа

5. **Fallback логика:**
   - Сначала пытается решить автоматически (PoW + API вызовы)
   - При любой ошибке автоматического решения открывается WebView
   - Пользователь решает капчу вручную

### Преимущества

- **Автоматическое решение** - большинство капч решается без участия пользователя
- **Fallback на WebView** - гарантия решения даже при сбое автоматического
- **Изоляция** - mutex предотвращает конфликты при множественных запросах
- **Bypass VPN** - WebView работает через физическую сеть, игнорируя туннель
- **Таймауты** - защита от бесконечного ожидания
