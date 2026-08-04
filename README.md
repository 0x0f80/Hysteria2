# hysteria2-setup

Установка VPN-сервера **Hysteria2** (QUIC/UDP) одной командой. Обход DPI/ТСПУ, Salamander-обфускация, маскировка под www.microsoft.com.

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

Вставьте ссылку `hysteria2://...` в **NekoBox** (Android/Windows), **Hiddify** или **v2rayN**.

> Hysteria2 работает по UDP. Если сеть режет UDP — смените порт или сеть.
