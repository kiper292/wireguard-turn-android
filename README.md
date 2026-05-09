# WireGuard Android с VK TURN Proxy

[English version (README.en.md)](README.en.md)

Это специализированный форк официального клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android) с интегрированной поддержкой **VK TURN Proxy**.

Проект позволяет инкапсулировать трафик WireGuard в потоки DTLS/TURN, используя инфраструктуру VK Calls. Это обеспечивает надежный способ обхода сетевых ограничений при сохранении высокой производительности и стабильности.

## Важное предупреждение

**Данный проект создан исключительно в учебных и исследовательских целях.**

Использование инфраструктуры VK Calls (TURN-серверов) без явного разрешения со стороны правообладателя может нарушать Условия использования сервиса и правила платформы VK. Автор проекта не несет ответственности за любой ущерб или нарушение правил, возникшее в результате использования данного программного обеспечения. Проект демонстрирует техническую возможность интеграции протоколов и не предназначен для нецелевого использования ресурсов сторонних сервисов.

## Ключевые особенности

- **Нативная интеграция**: TURN-клиент встроен напрямую в `libwg-go.so` для максимальной производительности и минимального расхода заряда батареи.
- **Два режима авторизации**:
  - **VK Link** — получение учетных данных TURN через анонимные токены VK Calls.
  - **WB** — получение учетных данных TURN через WB Stream API (гостевая регистрация → создание комнаты → LiveKit ICE).
- **Многопоточная балансировка**: Высокая производительность и надежность за счет параллельных потоков DTLS, агрегации по Session ID и Round-Robin балансировки исходящего трафика.
- **Кастомный DNS резолвер**: Все HTTP и WebSocket запросы проходят через встроенный DNS резолвер с защитой сокетов через VPN.
- **Оптимизация MTU**: Автоматическая установка MTU в 1280 при использовании TURN для стабильной работы инкапсулированных пакетов.
- **Автоматический рестарт при смене сети**: TURN автоматически переподключается при переключении между WiFi и 4G/5G с защитой от частых перезапусков (debounce).
- **Быстрое восстановление сети**: Сброс DNS и HTTP-соединений при смене сети для ускоренного переподключения.
- **Удобная настройка**: Параметры TURN хранятся прямо в стандартных `.conf` файлах WireGuard в виде специальных комментариев-метаданных (`#@wgt:`).

## Благодарности

Этот проект построен на базе:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — основное приложение VPN и пользовательский интерфейс.
2. **[vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — автор идеи и вдохновитель проекта.
3. **[lionheart](https://github.com/jaykaiperson/lionheart)** — исходная реализация режима WB для получения TURN credentials.

> **Важно**: Для корректной работы этого клиента (агрегация потоков по Session ID) рекомендуется использовать серверную часть v2 из форка [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy).

## Сборка

```bash
# Требуется Go 1.25+ и Android NDK 29
$ git clone --recurse-submodules https://github.com/your-repo/wireguard-turn-android
$ cd wireguard-turn-android
$ ./gradlew assembleRelease
```

## Настройка

Вы можете включить прокси в редакторе туннеля. Настройки будут добавлены в секцию Peer вашей конфигурации:

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
#@wgt:Mode = vk_link              # Режим авторизации: vk_link или wb
#@wgt:PeerType = turncoat_v3       # turncoat_v3 | proxy_v2 | proxy_v1 | wireguard
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4           # Потоков на один кэш credentials

# Advanced settings (optional)
#@wgt:TurnIP = 155.212.199.166      # Переопределить IP TURN сервера
#@wgt:TurnPort = 19302              # Переопределить порт TURN сервера
#@wgt:WatchdogTimeout = 30          # Таймаут неактивности (сек, 0=отключен)
#@wgt:WrapKey = <64-hex-key>        # WRAP/WARP ключ TURNcoat v3 (пусто=отключено)
```

**Примечание:** Параметр `PeerType` определяет режим работы:
- `turncoat_v3` — TURNcoat v3: DTLS + 19-byte Session ID handshake, совместим с сервером `TURNcoat` ветки `v3`
- `proxy_v2` (по умолчанию) — DTLS с передачей Session ID для агрегации потоков (сервер: [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy))
- `proxy_v1` — DTLS без Session ID handshake (сервер: [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy))
- `wireguard` — без DTLS, прямой relay (NoDTLS, для отладки или прямого подключения)

**Watchdog Timeout:** Параметр `WatchdogTimeout` активирует контроль неактивности для DTLS режима:
- `0` (по умолчанию) — watchdog отключен
- `≥5` — таймаут в секундах; если пакеты не получаются от TURN сервера в течение указанного времени, соединение переподключается

**WRAP/WARP:** Параметр `WrapKey` включает ChaCha20-обфускацию DTLS-пакетов для TURNcoat `v3`. Ключ должен совпадать с `server -wrap-key`; пустое значение сохраняет старое поведение.
- Применяется только к режимам `turncoat_v3`, `proxy_v2` и `proxy_v1`

Для получения подробной технической информации см. [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Donations / Поддержать разработчика

Are welcome here:

<img width="16" height="16" alt="bitcoin" src="https://github.com/user-attachments/assets/ea73b5cc-cba4-4428-8704-d5345acf58d4" /> BTC:
```plaintext
1ERKmMSyfxtKNNpU3TeaYCaJfDKY9s8jdX
```

<img width="16" height="16" alt="ethereum" src="https://github.com/user-attachments/assets/2a2fcba2-66d9-4eb9-a5e7-35e6889f76f0" /> ETH Ethereum (ERC20):
```plaintext
0xfa8fdae60010e3d6b446d7479a9ccacfc56c0936
```

<img width="16" height="16" alt="tether" src="https://github.com/user-attachments/assets/9f88aa41-fcfd-48ea-ae5a-c0bef933666d" /> USDT TRON (TRC20):
```plaintext
TMgojRMiya1nJ2uEtw8u7p5YZ9J7Ykdmd9
```

<img width="16" height="16" alt="tether" src="https://github.com/user-attachments/assets/9f88aa41-fcfd-48ea-ae5a-c0bef933666d" /> USDT APTOS:
```plaintext
0x741a8b707b75aa57dc603fa30d1c4750198866b0e9eb6d9a7a1a7dde8ec7f4d2
```

<img width="16" height="16" alt="tontoken" src="https://github.com/user-attachments/assets/14e9293f-5ca2-49fe-b5ae-4bf48be065a4" /> TON / USDT TON:
```plaintext
UQD0BQTBSVo19hrjKyXnRc61MXW0j9dTZaLEXOUJwxLT2qRQ
```

<img width="16" height="16" alt="litecoin" src="https://github.com/user-attachments/assets/193b09c3-eca6-4feb-b887-a603813c11eb" /> LTC:
```plaintext
La2H1YD2zKxqhsziGrx74anjJYwAQJ67er
```

## Участие в проекте

Для перевода интерфейса используйте оригинальный [WireGuard Crowdin](https://crowdin.com/project/WireGuard). При обнаружении технических ошибок, связанных с интеграцией TURN, пожалуйста, создавайте Issue в этом репозитории.
