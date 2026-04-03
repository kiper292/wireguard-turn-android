# WireGuard Android с VK TURN Proxy
ФОРК kiper292/wireguard-turn-android!!!


[English version (README.en.md)](README.en.md)

Это специализированный форк официального клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android) с интегрированной поддержкой **VK TURN Proxy**.

Проект позволяет инкапсулировать трафик WireGuard в потоки DTLS/TURN, используя инфраструктуру VK Calls. Это обеспечивает надежный способ обхода сетевых ограничений при сохранении высокой производительности и стабильности.

## Важное предупреждение

**Данный проект создан исключительно в учебных и исследовательских целях.**

Использование инфраструктуры VK Calls (TURN-серверов) без явного разрешения со стороны правообладателя может нарушать Условия использования сервиса и правила платформы VK. Автор проекта не несет ответственности за любой ущерб или нарушение правил, возникшее в результате использования данного программного обеспечения. Проект демонстрирует техническую возможность интеграции протоколов и не предназначен для нецелевого использования ресурсов сторонних сервисов.

## Ключевые особенности

- **Нативная интеграция**: TURN-клиент встроен напрямую в `libwg-go.so` для максимальной производительности и минимального расхода заряда батареи.
- **Авторизация VK**: Автоматическое получение учетных данных TURN через анонимные токены VK Calls.
- **Многопоточная балансировка**: Высокая производительность и надежность за счет параллельных потоков DTLS, агрегации по Session ID и Round-Robin балансировки исходящего трафика.
- **Оптимизация MTU**: Автоматическая установка MTU в 1280 при использовании TURN для стабильной работы инкапсулированных пакетов.
- **Автоматический рестарт при смене сети**: TURN автоматически переподключается при переключении между WiFi и 4G/5G с защитой от частых перезапусков (debounce).
- **Быстрое восстановление сети**: Сброс DNS и HTTP-соединений при смене сети для ускоренного переподключения.
- **Удобная настройка**: Параметры TURN хранятся прямо в стандартных `.conf` файлах WireGuard в виде специальных комментариев-метаданных (`#@wgt:`).

## Благодарности

Этот проект построен на базе:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — основное приложение VPN и пользовательский интерфейс.
2. **[vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy)** — серверная часть прокси (v2), необходимая для работы данного клиента.

> **Важно**: Для корректной работы этого клиента (агрегация потоков по Session ID) необходимо использовать серверную часть из форка [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy).

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
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000

# Advanced settings (optional)
#@wgt:TurnIP = 155.212.199.166      # Переопределить IP TURN сервера
#@wgt:TurnPort = 19302              # Переопределить порт TURN сервера
#@wgt:NoDTLS = false                # Отключить DTLS (для прямого доступа к серверу WireGuard)
```

**Примечание:** Режим `NoDTLS = true` предназначен для отладки или прямого подключения к WireGuard серверу через TURN. Он несовместим с прокси-сервером, который требует DTLS handshake.

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
