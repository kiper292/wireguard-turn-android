# Интеграция VK TURN Proxy (Архитектура)

В данном документе описана архитектура интеграции VK TURN Proxy в форк клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android).

## 1. Нативный уровень (Go / JNI)

### `tunnel/tools/libwg-go/jni.c`

- **`wgProtectSocket(int fd)`**: Функция для вызова `VpnService.protect(fd)` через JNI. Позволяет TURN-клиенту выводить трафик за пределы VPN-туннеля.
  - Валидация fd (возвращает -1 при невалидном fd)
  - Логирование результата (SUCCESS/FAILED)
  - **bindSocket()** — привязка сокета к кэшированному Network object для маршрутизации через правильный интерфейс

- **`wgTurnProxyStart/Stop`**: Экспортированные методы для управления жизненным циклом прокси-сервера.
  - Принимает `networkHandle` (long long) для привязки к конкретному Network
  - Вызывает `update_current_network()` для кэширования Network object

- **`wgNotifyNetworkChange()`**: Функция для сброса DNS resolver и HTTP-соединений при переключении сети (WiFi <-> 4G). Обеспечивает быстрое восстановление соединения после смены сетевого интерфейса.

- **`update_current_network()`**: Внутренняя функция для кэширования Network object и NetworkHandle. Используется для `bindSocket()` при защите сокетов.

- **Стабилизация ABI**: Использование простых C-типов (`const char *`, `int`, `long long`) для передачи параметров прокси, что устраняет ошибки выравнивания памяти в Go-структурах на разных архитектурах. Параметр `udp` имеет тип `int` для корректной работы JNI.

- **Детальное логирование**: `wgProtectSocket()` логирует валидацию fd, вызов protect() и результат (SUCCESS/FAILED), а также результат bindSocket().

### `tunnel/tools/libwg-go/turn-client.go`

- **Session ID Handshake (Multi-User Support)**: Клиент генерирует уникальный 16-байтный UUID при каждом запуске туннеля и отправляет его первым пакетом после DTLS рукопожатия в каждом потоке. Это позволяет серверу агрегировать несколько DTLS-сессий в одно стабильное UDP-соединение до WireGuard сервера, решая проблему "Endpoint Thrashing".
- **Round-Robin Load Balancing**: Реализация Hub-сервера, который поддерживает `n` параллельных DTLS-соединений. Вместо использования одного «липкого» потока, клиент равномерно распределяет исходящие пакеты WireGuard между всеми готовыми (ready) DTLS-соединениями. Это повышает общую пропускную способность и устойчивость к потерям в отдельных потоках.
- **Интегрированная авторизация VK**: Реализован полный цикл получения токенов (VK Calls -> OK.ru -> TURN credentials) внутри Go.
- **Кэширование TURN credentials**: Credentials кэшируются на 9 минут (10 минут TTL - 1 минута запас). При реконнекте потоков используются кэшированные данные, что устраняет дублирующие запросы к VK API. Кэш инвалидируется при смене сети через `wgNotifyNetworkChange()`.
- **Защита сокетов**: Все исходящие соединения (HTTP, UDP, TCP) используют `Control` функцию с вызовом `wgProtectSocket`.
- **Custom DNS Resolver**: Встроенный резолвер с обходом системных DNS Android (localhost) для обеспечения работоспособности в условиях активного VPN.
- **Таймаут DTLS handshake**: Явный 10-секундный таймаут предотвращает зависания при потере пакетов.
- **Staggered запуск потоков**: Потоки запускаются с задержкой 200ms для снижения нагрузки на сервер и предотвращения "шторма" подключений.
- **Watchdog реконнекта**: Автоматическое восстановление соединения при отсутствии ответа в течение 30 секунд.
- **No DTLS режим**: Опциональный режим работы без DTLS-инкапсуляции для прямого подключения к WireGuard серверу через TURN. Предназначен для отладки или специфичных сетевых условий. Реализован в методе `runNoDTLS()`.
- **Метрики для диагностики**: Счётчики ошибок для отслеживания проблем (dtlsTxDropCount, dtlsRxErrorCount, relayTxErrorCount, relayRxErrorCount, noDtlsTxDropCount, noDtlsRxErrorCount).
- **Улучшенная обработка ошибок аутентификации**: Функции `isAuthError()` и `handleAuthError()` для детектирования и обработки устаревших credentials.
- **Deadline management**: Явные дедлайны для handshake (10с), session ID (5с) и обновления дедлайнов каждые 5с (30с таймаут).
- **Connected UDP/TCP abstraction**: Интерфейс `net.PacketConn` для унификации обработки UDP и TCP соединений.

---

## 2. Слой конфигурации (Java)

### `tunnel/src/main/java/com/wireguard/config/`

- **`Peer.java`**: Поддержка `extraLines` — списка строк, начинающихся с `#@`. Это позволяет хранить метаданные прокси прямо в `.conf` файле, не нарушая совместимость с другими клиентами.
- **`Config.java`**: Парсер корректно передаёт комментарии с префиксом `#@` в соответствующие секции.

---

## 3. Логика управления и UI (Kotlin)

### `ui/src/main/java/com/wireguard/android/turn/TurnProxyManager.kt`

- **`TurnSettings`**: Модель данных для настроек прокси (VK Link, Peer, Port, Streams).
- **`TurnConfigProcessor`**: Логика инъекции/извлечения настроек из текста конфигурации. Метод `modifyConfigForActiveTurn` динамически подменяет `Endpoint` на `127.0.0.1`, **принудительно устанавливает MTU в 1280**, и **PersistentKeepalive=25** (для DTLS режима) для компенсации оверхеда инкапсуляции и поддержания соединения.
- **`TurnProxyManager`**: Управляет нативным процессом прокси.

  **Синхронизация при запуске:**
  - Вызывает `TurnBackend.waitForVpnServiceRegistered(2000)` для ожидания регистрации JNI
  - После подтверждения JNI запускает `wgTurnProxyStart()` с параметром `networkHandle`
  - Это гарантирует что `VpnService.protect()` будет работать для всех сокетов TURN

  **PhysicalNetworkMonitor:**
  - Отдельный класс `PhysicalNetworkMonitor` отслеживает физические сети (WiFi, Cellular)
  - Игнорирует VPN интерфейсы для избежания обратной связи с собственным туннелем
  - Приоритет выбора: WiFi > Cellular > любая другая сеть с интернетом
  - Debounce 1500ms через Flow для фильтрации быстрых переключений
  - `currentNetwork` — синхронное получение текущего лучшего сети без debounce
  - `bestNetwork` — Flow с debounce 1500ms и distinctUntilChanged

  **Автоматический рестарт:**
  - При смене физического типа сети (WiFi ↔ Cellular) TURN переподключается без участия пользователя
  - Вызывает `wgNotifyNetworkChange()` для сброса DNS/HTTP в Go слое
  - Экспоненциальный backoff при неудачах: 2с → 5с → 15с (при более 5 попытках)
  - Флаг `userInitiatedStop` — не рестартировать, если пользователь явно остановил туннель
  - `operationMutex` — мьютекс для сериализации операций start/stop и предотвращения гонок

### `tunnel/src/main/java/com/wireguard/android/backend/TurnBackend.java`

- **AtomicReference для CompletableFuture**: Атомарная замена `CompletableFuture<VpnService>` через `getAndSet()` предотвращает гонки при быстрой смене состояний сервиса.
- **CountDownLatch для синхронизации JNI**: Latch сигнализирует что JNI зарегистрирован и готов защищать сокеты.
- **`waitForVpnServiceRegistered(timeout)`**: Метод для ожидания регистрации JNI перед запуском TURN прокси.
- **`wgNotifyNetworkChange()`**: Native функция для сброса DNS/HTTP при смене сети.
- **`wgTurnProxyStart(..., networkHandle)`**: Native функция принимает `networkHandle` (long) для привязки сокетов к конкретному Network.

### `tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java`

- **Правильный порядок инициализации VpnService:**
  1. В `onCreate()` сначала вызывается `TurnBackend.onVpnServiceCreated(this)` для регистрации в JNI
  2. Затем завершается `vpnService.complete(this)` для Java кода
  - Это гарантирует что JNI готов до того как TurnProxyManager получит Future

- **TURN запускается после создания туннеля:**
  - В `setStateInternal()` TURN прокси запускается после `builder.establish()`
  - Это гарантирует что `VpnService.protect()` будет работать для сокетов TURN

- **Регистрация VpnService:**
  - `TurnBackend.onVpnServiceCreated()` вызывается в `onCreate()` для регистрации в JNI

### `ui/src/main/java/com/wireguard/android/model/TunnelManager.kt`

- **Запуск TURN после создания туннеля:**
  - TURN прокси запускается через `TurnProxyManager.onTunnelEstablished()` после того как `GoBackend.setStateInternal()` завершит создание туннеля

---

## 4. Протокол взаимодействия

Для обеспечения стабильности соединения в условиях мультиплексирования (Multi-Stream) используется следующий протокол:

1. **DTLS Handshake**: Стандартное установление защищенного соединения (с таймаутом 10 секунд).
2. **Session Identification**: Клиент отправляет 16 байт (Raw UUID) непосредственно в поток DTLS.
3. **Tunnel Traffic**: После отправки UUID начинается двусторонний обмен пакетами WireGuard.

Это позволяет прокси-серверу идентифицировать сессию пользователя и поддерживать стабильный `Endpoint` на стороне WireGuard сервера, вне зависимости от количества активных DTLS-потоков или смены IP-адресов клиента.

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
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:TurnIP = 1.2.3.4        # (optional) Override TURN server IP
#@wgt:TurnPort = 12345        # (optional) Override TURN server port
#@wgt:NoDTLS = true           # (optional) Disable DTLS obfuscation
```

Эти строки игнорируются стандартными клиентами WireGuard, но считываются данным форком при загрузке.

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

### No DTLS

Отключает DTLS-инкапсуляцию трафика WireGuard. Предназначен для:
- Отладки соединения
- Прямого подключения к WireGuard серверу через TURN
- Сценариев, где DTLS не требуется

**Важно:** Режим No DTLS несовместим с нашим прокси-сервером, который требует DTLS handshake и Session ID. Используйте только для прямого подключения к WireGuard серверу.

**Пример:**
```
#@wgt:NoDTLS = true
```

### PersistentKeepalive (автоматический)

При включённом DTLS режиме (`#@wgt:NoDTLS = false` или не указано), `TurnConfigProcessor.modifyConfigForActiveTurn` **автоматически устанавливает PersistentKeepalive=25** для всех пиров.

**Назначение:**
- Поддержание NAT mapping для DTLS соединения
- Предотвращение таймаута UDP сессии на стороне TURN сервера
- Значение 25 секунд выбрано как оптимальный баланс между нагрузкой и надёжностью

**Логика:**
- Если в конфиге уже указан PersistentKeepalive ≤ 25, используется оригинальное значение
- Если PersistentKeepalive не указан или > 25, устанавливается 25
- В режиме No DTLS PersistentKeepalive не модифицируется

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

Настройки TURN сохраняются в отдельном JSON-файле `<tunnel>.turn.json` рядом с конфигом WireGuard. Это позволяет:
- Хранить настройки независимо от конфига
- Обновлять конфиг без потери настроек TURN
- Быстро загружать/применять настройки

**Формат файла:**
```json
{
  "enabled": true,
  "peer": "89.250.227.41:56000",
  "vkLink": "https://vk.com/call/join/...",
  "streams": 4,
  "useUdp": false,
  "localPort": 9000,
  "turnIp": "",
  "turnPort": 0,
  "noDtls": false
}
```

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
    → wgTurnProxyStart(..., networkHandle) ← Запуск TURN с handle сети
      → update_current_network() в JNI      ← Кэширование Network object
      → VK Auth для получения credentials
      → Подключение к TURN серверу (4 потока)
      → DTLS handshake для каждого потока
      → wgProtectSocket() + bindSocket() для всех сокетов
```

**Преимущества:**
- TURN запускается после создания туннеля, что гарантирует работу `VpnService.protect()` для всех сокетов
- Явная синхронизация через CountDownLatch исключает гонки условий
- Сокеты WireGuard защищаются до запуска TURN
- **networkHandle** передаётся в Go для привязки сокетов к конкретному Network через `bindSocket()`
- **PhysicalNetworkMonitor** отслеживает физические сети и автоматически перезапускает TURN при смене типа сети

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
