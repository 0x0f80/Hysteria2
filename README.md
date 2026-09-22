# hysteria2-setup

Установка VPN-сервера **Hysteria2** (QUIC/UDP) одной командой. Обход DPI/ТСПУ, Salamander-обфускация (трафик выглядит как случайный UDP).

## Установка

```bash
wget -qO install_hysteria2.sh https://raw.githubusercontent.com/0x0f80/Hysteria2/main/install_hysteria2.sh && bash install_hysteria2.sh
```

Требуется: Ubuntu/Debian, root, x86_64 или aarch64.

## Управление

```bash
h            # меню
hynewuser    # создать пользователя
hyuserlist   # список пользователей
hystatus     # статус сервиса
```

## Клиенты

Вставьте ссылку `hysteria2://...` в **v2rayNG** (Android), **v2rayN** (Windows), **NekoBox** или **Hiddify**.

> В ссылке есть отпечаток сертификата (`pinSHA256`) — с ним работают и клиенты на ядре Xray.

> Hysteria2 работает по UDP. Если сеть режет UDP (часто — мобильные операторы), используйте [xray-reality-setup](https://github.com/0x0f80/xray-reality-setup).
